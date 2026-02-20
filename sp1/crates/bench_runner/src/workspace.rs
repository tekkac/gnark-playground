use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};

pub struct RunWorkspace {
    path: PathBuf,
    cleaned: bool,
}

impl RunWorkspace {
    pub fn new(run_id: &str) -> Result<Self> {
        let path = PathBuf::from(format!("/tmp/sp1-bench/{run_id}"));
        fs::create_dir_all(&path).with_context(|| format!("create {}", path.display()))?;
        Ok(Self {
            path,
            cleaned: false,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn install_signal_handler(&self) -> Result<()> {
        let path = self.path.clone();
        let tripped = Arc::new(AtomicBool::new(false));
        let tripped_inner = Arc::clone(&tripped);

        ctrlc::set_handler(move || {
            if tripped_inner.swap(true, Ordering::SeqCst) {
                return;
            }
            let _ = fs::remove_dir_all(&path);
            eprintln!(
                "received interrupt: cleaned ephemeral workspace {}",
                path.display()
            );
            std::process::exit(130);
        })
        .map_err(|e| anyhow!("install ctrlc handler: {e}"))
    }

    pub fn cleanup_strict(&mut self) -> Result<()> {
        fs::remove_dir_all(&self.path)
            .with_context(|| format!("remove {}", self.path.display()))?;
        if self.path.exists() {
            return Err(anyhow!(
                "workspace still exists after cleanup: {}",
                self.path.display()
            ));
        }
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for RunWorkspace {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RunWorkspace;

    #[test]
    fn cleans_workspace_strictly() {
        let mut ws = RunWorkspace::new("test-cleanup").unwrap();
        let p = ws.path().to_path_buf();
        std::fs::write(p.join("tmp.txt"), b"x").unwrap();
        ws.cleanup_strict().unwrap();
        assert!(!p.exists());
    }
}
