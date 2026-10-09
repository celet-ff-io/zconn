use std::process::Stdio;

use tap::Pipe as _;
use tokio::{
    io::{AsyncBufRead, AsyncWrite, BufReader, empty, sink},
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

    let mut client_link = JsonlLink::new(&mut *client_in, &mut *client_out);
    // Handshake with client: client - hs -> translator
    handshake_with_client(&mut client_link).await?;

    // Data phase
    let client_pump = pump_client_to_core(&mut *client_in, core_stdin);
    let core_pump = pump_core_to_client(core_stdout, &mut *client_out);
    tokio::pin!(client_pump, core_pump);
    tokio::select! {
        biased;
        client_res = &mut client_pump => {
            let core_res = core_pump.await;
            client_res.and(core_res)
        }
        core_res = &mut core_pump => match core_res {
            Ok(()) => CorePError::UnexpectedEof.pipe(crate::Error::from).pipe(Err),
            e => e,
        },
    }?;

    let status = core_process.wait().await.map_err(CorePError::from)?;
    if !status.success() {
        CorePError::BadExitStatus(status).pipe(Err)?;
    }
    log::info!("core exit 0");
    Ok(())
}

/// client → core pump
async fn pump_client_to_core<C, S>(client_in: C, mut core_stdin: S) -> crate::Result<()>
where
    C: AsyncBufRead + Unpin,
    S: AsyncWrite + Unpin,
{
    let mut from_client = JsonlLink::new(client_in, sink());
    let mut to_core = ProtobufLink::new(empty(), &mut core_stdin);
    while let Some(frame) = from_client
        .read_frame::<IncomingFrame>()
        .await
        .map_err(ClientPError::from)?
    {
        log::trace!("client frame in (text of {} byte(s))", frame.text.len());
        to_core
            .write_frame(&frame)
            .await
            .map_err(CorePError::from)?;
        log::trace!("frame out to core (text of {} byte(s))", frame.text.len());
    }
    log::info!("client EOF; core stdin dropped (EOF to core)");
    Ok(())
}

/// core → client pump
async fn pump_core_to_client<R, C>(core_stdout: R, client_out: C) -> crate::Result<()>
where
    R: AsyncBufRead + Unpin,
    C: AsyncWrite + Unpin,
{
    let mut from_core = ProtobufLink::new(core_stdout, sink());
    let mut to_client = JsonlLink::new(empty(), client_out);
    while let Some(frame) = from_core
        .read_frame::<OutgoingFrame>()
        .await
        .map_err(CorePError::from)?
    {
        log::trace!("core frame in (text of {} byte(s))", frame.text.len());
        to_client
            .write_frame(&frame)
            .await
            .map_err(ClientPError::from)?;
        log::trace!("frame out to client (text of {} byte(s))", frame.text.len());
    }
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
        return CorePError::VersionMismatch {
            this: PROTOCOL_VERSION,
            received: core_version,
        }
        .pipe(Err);
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
        return ClientPError::VersionMismatch {
            this: PROTOCOL_VERSION,
            received: client_version,
        }
        .pipe(Err);
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
