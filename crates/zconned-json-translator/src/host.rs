use std::process::Stdio;

use tap::Pipe as _;
use tokio::{
    io::{AsyncBufRead, AsyncWrite, BufReader},
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
    let core_process = spawn_core(zconned_bin)?;
    let mut core_link = ProtobufLink::new(
        take_stdio(core_process.stdout, "stdout")?.pipe(BufReader::new),
        take_stdio(core_process.stdin, "stdin")?,
    );
    // Handshake with core: translator - hs -> core
    handshake_with_core(&mut core_link).await?;

    let mut client_link = JsonlLink::new(client_in, client_out);
    // Handshake with client: client - hs -> translator
    handshake_with_client(&mut client_link).await?;

    while let Some(frame_from_client) = client_link
        .read_frame::<IncomingFrame>()
        .await
        .map_err(ClientPError::from)?
    {
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

    Ok(())
}

#[inline]
fn spawn_core(core: &str) -> Result<Child, CorePError> {
    Command::new(core)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(CorePError::ProcessSpawnFailed)
}

fn take_stdio<T>(mut opt: Option<T>, name: &str) -> crate::Result<T> {
    opt.take()
        .ok_or_else(|| CorePError::ProcessStdioPipeConsumed {
            name: name.to_owned(),
        })?
        .pipe(Ok)
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
        .await?
        .ok_or(CorePError::UnexpectedEof)?;
    if core_version != PROTOCOL_VERSION {
        CorePError::VersionMismatch {
            this: PROTOCOL_VERSION,
            received: core_version,
        }
        .pipe(Err)?;
    }

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
        .await?
        .ok_or(ClientPError::UnexpectedEof)?;
    if client_version != PROTOCOL_VERSION {
        ClientPError::VersionMismatch {
            this: PROTOCOL_VERSION,
            received: client_version,
        }
        .pipe(Err)?;
    }

    client_link
        .write_frame(&Handshake {
            version: PROTOCOL_VERSION,
        })
        .await?;

    Ok(())
}
