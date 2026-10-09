use std::process::Stdio;

use tap::Pipe as _;
use tokio::{
    io::{AsyncBufRead, AsyncReadExt, AsyncWrite, BufReader},
    process::{Child, Command},
};
use zconned_io_link::{
    ReadLink, WriteLink, jsonl::LinkStruct as JsonlLink, protobuf::LinkStruct as ProtobufLink,
};
use zconned_types::{Handshake, IncomingFrame, OutgoingFrame, PROTOCOL_VERSION};

use crate::error::{client_process::Error as ClientPError, core_process::Error as CorePError};

pub async fn run<R, W>(
    zconned_bin: &str,
    client_in: &mut R,
    client_out: &mut W,
) -> crate::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    log::info!("session starting; spawning core: {zconned_bin}");
    let mut core_process = spawn_core(zconned_bin)?;
    let mut core_stdin = take_stdio(core_process.stdin.take(), "stdin")?;
    let mut core_stdout = BufReader::new(take_stdio(core_process.stdout.take(), "stdout")?);
    let mut core_link = ProtobufLink::new(&mut core_stdout, &mut core_stdin);

    // Handshake with core: translator - hs -> core
    handshake_with_core(&mut core_link).await?;

    let mut client_link = JsonlLink::new(client_in, client_out);
    // Handshake with client: client - hs -> translator
    handshake_with_client(&mut client_link).await?;

    // Data phase
    while let Some(frame_from_client) = client_link
        .read_frame::<IncomingFrame>()
        .await
        .map_err(ClientPError::from)?
    {
        log::debug!(
            "client frame in (text of {} byte(s))",
            frame_from_client.text.len()
        );
        core_link
            .write_frame(&frame_from_client)
            .await
            .map_err(CorePError::from)?;

        let frame_from_core: OutgoingFrame = core_link
            .read_frame()
            .await
            .map_err(CorePError::from)?
            .ok_or(CorePError::UnexpectedEof)?;
        client_link
            .write_frame(&frame_from_core)
            .await
            .map_err(ClientPError::from)?;
    }

    // Send EOF signal to core via its stdin
    log::info!("client EOF; closing core stdin and reaping core");
    drop(core_link);
    drop(core_stdin);
    loop {
        let mut chunk = [0u8; 8192];
        if core_stdout
            .read(&mut chunk)
            .await
            .map_err(CorePError::from)?
            == 0
        {
            break;
        }
    }
    let status = core_process.wait().await.map_err(CorePError::from)?;
    if !status.success() {
        return Err(CorePError::BadExitStatus(status).into());
    }
    log::info!("core exit 0");
    Ok(())
}

#[inline]
fn spawn_core(core: &str) -> Result<Child, CorePError> {
    log::info!("spawning core process `{core}`");
    Command::new(core)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        // If the translator itself dies mid-session, do not leave a
        // running core behind.
        .kill_on_drop(true)
        .spawn()
        .map_err(CorePError::ProcessSpawnFailed)
}

fn take_stdio<T>(mut opt: Option<T>, name: &str) -> Result<T, CorePError> {
    opt.take()
        .ok_or_else(|| CorePError::ProcessStdioPipeConsumed {
            name: name.to_owned(),
        })
}

/// translator - hs -> core
#[inline]
async fn handshake_with_core<R, W>(core_link: &mut ProtobufLink<R, W>) -> Result<(), CorePError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    Handshake {
        version: PROTOCOL_VERSION,
    }
    .pipe_ref(|m| core_link.write_frame(m))
    .await?;

    let Handshake {
        version: core_version,
    } = core_link
        .read_frame()
        .await
        .map_err(CorePError::from)?
        .ok_or(CorePError::UnexpectedEof)?;
    if core_version != PROTOCOL_VERSION {
        return Err(CorePError::VersionMismatch {
            this: PROTOCOL_VERSION,
            received: core_version,
        });
    }

    log::info!("core handshake ok (version {PROTOCOL_VERSION})");
    Ok(())
}

/// translator - hs -> client
#[inline]
async fn handshake_with_client<R, W>(client_link: &mut JsonlLink<R, W>) -> Result<(), ClientPError>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Handshake {
        version: client_version,
    } = client_link
        .read_frame()
        .await
        .map_err(ClientPError::from)?
        .ok_or(ClientPError::UnexpectedEof)?;
    if client_version != PROTOCOL_VERSION {
        return Err(ClientPError::VersionMismatch {
            this: PROTOCOL_VERSION,
            received: client_version,
        });
    }

    client_link
        .write_frame(&Handshake {
            version: PROTOCOL_VERSION,
        })
        .await
        .map_err(ClientPError::from)?;
    log::info!("client handshake acked (version {PROTOCOL_VERSION})");

    Ok(())
}
