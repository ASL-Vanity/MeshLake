use super::*;

#[cfg(windows)]
fn pick_path(current: &str, save: bool) -> Result<Option<String>, String> {
    use windows_sys::Win32::UI::{Controls::Dialogs::*, Input::KeyboardAndMouse::GetActiveWindow};
    let mut buffer = vec![0u16; 32768];
    let initial: Vec<u16> = current.encode_utf16().collect();
    if initial.len() >= buffer.len() {
        return Err("路径过长 / Path too long".into());
    }
    buffer[..initial.len()].copy_from_slice(&initial);
    let filter: Vec<u16> = "All files\0*.*\0\0".encode_utf16().collect();
    // The native modal owns its message loop; NOCHANGEDIR protects future relative paths.
    let mut dialog: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    dialog.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    dialog.hwndOwner = unsafe { GetActiveWindow() };
    dialog.lpstrFile = buffer.as_mut_ptr();
    dialog.nMaxFile = buffer.len() as u32;
    dialog.lpstrFilter = filter.as_ptr();
    dialog.nFilterIndex = 1;
    dialog.Flags = OFN_EXPLORER
        | OFN_NOCHANGEDIR
        | OFN_PATHMUSTEXIST
        | if save { 0 } else { OFN_FILEMUSTEXIST };
    let accepted = unsafe {
        if save {
            GetSaveFileNameW(&mut dialog)
        } else {
            GetOpenFileNameW(&mut dialog)
        }
    };
    if accepted == 0 {
        let error = unsafe { CommDlgExtendedError() };
        return if error == 0 {
            Ok(None)
        } else {
            Err(format!("文件对话框失败 / File dialog failed: {error}"))
        };
    }
    let end = buffer
        .iter()
        .position(|&ch| ch == 0)
        .unwrap_or(buffer.len());
    String::from_utf16(&buffer[..end])
        .map(Some)
        .map_err(|_| "路径编码无效 / Invalid path encoding".into())
}

#[cfg(not(windows))]
fn pick_path(_: &str, _: bool) -> Result<Option<String>, String> {
    Err("请在路径框输入文件位置。 / Enter a path in the text field.".into())
}

pub(super) fn browse(
    ui: &mut egui::Ui,
    path: &mut String,
    save: bool,
    label: &str,
    message: &mut String,
) {
    if ui.button(label).clicked() {
        match pick_path(path, save) {
            Ok(Some(selected)) => *path = selected,
            Ok(None) => {}
            Err(error) => *message = error,
        }
    }
}
