/** 与服务端 pwd_problem / multisync.py:_pwd_problem 同规则的前端预检。 */
export function pwdProblem(pw: string, label = "密码"): string {
  const s = pw ?? "";
  if (s.length < 8) return `${label}至少 8 位`;
  if (label === "安全码" && s.length > 32) return "安全码最多 32 位";
  if (s.length > 64) return `${label}过长`;
  const hasLetter = /[A-Za-z]/.test(s);
  const hasDigit = /[0-9]/.test(s);
  if (!hasLetter || !hasDigit) return `${label}需同时包含字母和数字`;
  if (s !== s.trim()) return `${label}首尾不能是空格`;
  return "";
}
