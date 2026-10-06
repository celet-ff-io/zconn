use std::process::Stdio;

use tap::Pipe as _;
use tokio::{
    io::{AsyncBufRead, AsyncWrite, BufReader},
    process::{Child, Command},
};
use zconned_types::{Handshake, IncomingFrame, OutgoingFrame, PROTOCOL_VERSION};

use crate::{
    Result,
    error::{client_process::Error as ClientPError, core_process::Error as CorePError},
    link::{ReadLink, WriteLink},
};

pub async fn run<R, W>(zconned_bin: &str, client_in: &mut R, client_out: &mut W) -> Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let core_process = spawn_core(zconned_bin)?;
    let mut core_link = crate::link::protobuf::LinkStruct::new(
        take_stdio(core_process.stdout, "stdout")?.pipe(BufReader::new),
        take_stdio(core_process.stdin, "stdin")?,
    );

    // Handshake with core: translator - hs -> core
    Handshake { version: 1 }
        .pipe_ref(|m| core_link.write_frame(m))
        .await
        .map_err(CorePError::from)?;

    let Handshake {
        version: core_version,
    } = core_link
        .read_frame()
        .await
        .map_err(CorePError::from)?
        .ok_or(CorePError::UnexpectedEof)?;
    if core_version != PROTOCOL_VERSION {
        CorePError::VersionMismatch {
            this: PROTOCOL_VERSION,
            received: core_version,
        }
        .pipe(Err)?;
    }

    // Handshake with client: client - hs -> translator
    let mut client_link = crate::link::jsonl::LinkStruct::new(client_in, client_out);
    let Handshake {
        version: client_version,
    } = client_link
        .read_frame()
        .await
        .map_err(ClientPError::from)?
        .ok_or(ClientPError::UnexpectedEof)?;
    if client_version != PROTOCOL_VERSION {
        ClientPError::VersionMismatch {
            this: PROTOCOL_VERSION,
            received: client_version,
        }
        .pipe(Err)?;
    }

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
fn spawn_core(core: &str) -> core::result::Result<Child, CorePError> {
    Command::new(core)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(CorePError::ProcessSpawnFailed)
}

fn take_stdio<T>(mut opt: Option<T>, name: &str) -> Result<T> {
    opt.take()
        .ok_or_else(|| CorePError::ProcessStdioPipeConsumed {
            name: name.to_owned(),
        })?
        .pipe(Ok)
}
