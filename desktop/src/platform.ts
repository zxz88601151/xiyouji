/** 是否在 Tauri 壳里运行（npm run dev 的浏览器预览为 false）。 */
export function isTauri(): boolean {
  return (
    typeof window !== "undefined" &&
    ("__TAURI_INTERNALS__" in window || "__TAURI__" in window)
  );
}

export async function invokeCmd<T>(
  cmd: string,
  args?: Record<string, unknown>
): Promise<T> {
  const core = await import("@tauri-apps/api/core");
  return core.invoke<T>(cmd, args);
}

/** 浏览器预览用的开发机器码；真实机器码由 Rust 读 MachineGuid 计算。 */
export const DEV_MACHINE = "WEBBROWSER000000";
