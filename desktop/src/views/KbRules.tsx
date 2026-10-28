/**
 * 按键规则编辑器（S2）：复刻 multisync.py KbRuleDialog 的语义与文案。
 * 表内键由规则接管（可映射/延迟/连发），表外键仍按键盘同步原样转发。
 * S2 用下拉选择键位（S3 接钩子后再换回"按键捕获"按钮）。
 */
import { useState } from "react";
import {
  DEFAULT_KB_RULES,
  RULE_MAX_DELAY_MS,
  RULE_MAX_TIMES,
  VK_CHOICES,
  vkName,
  type KbRule,
} from "../engine/api";

interface Props {
  rules: KbRule[];
  onApply: (rules: KbRule[]) => void;
  onClose: () => void;
}

export function KbRules({ rules, onApply, onClose }: Props) {
  const [rows, setRows] = useState<KbRule[]>(() =>
    (rules.length ? rules : DEFAULT_KB_RULES).map((r) => ({ ...r }))
  );
  const [sel, setSel] = useState<Set<number>>(new Set());

  function patch(i: number, p: Partial<KbRule>) {
    setRows((rs) => rs.map((r, j) => (j === i ? { ...r, ...p } : r)));
  }

  function addRow() {
    setRows((rs) => [...rs, { on: true, src: 0, dst: 0, delay: 0, times: 1 }]);
  }

  function delRows() {
    const drop = sel.size ? sel : new Set([rows.length - 1]);
    setRows((rs) => rs.filter((_, i) => !drop.has(i)));
    setSel(new Set());
  }

  function reset() {
    setRows(DEFAULT_KB_RULES.map((r) => ({ ...r })));
    setSel(new Set());
  }

  function toggleSel(i: number) {
    setSel((s) => {
      const n = new Set(s);
      if (n.has(i)) n.delete(i);
      else n.add(i);
      return n;
    });
  }

  function apply() {
    // 主号键或次号键没设置的整行丢弃（不打断用户），与 result_rules 一致
    const out = rows
      .filter((r) => r.src > 0 && r.dst > 0)
      .map((r) => ({
        on: r.on,
        src: Math.trunc(r.src),
        dst: Math.trunc(r.dst),
        delay: Math.max(0, Math.min(RULE_MAX_DELAY_MS, Math.trunc(r.delay) || 0)),
        times: Math.max(1, Math.min(RULE_MAX_TIMES, Math.trunc(r.times) || 1)),
      }));
    onApply(out);
  }

  const keySelect = (i: number, which: "src" | "dst") => (
    <select
      className="select mini"
      value={rows[i][which]}
      onChange={(e) => patch(i, { [which]: Number(e.target.value) })}
    >
      <option value={0}>未设置</option>
      {VK_CHOICES.map((vk) => (
        <option key={vk} value={vk}>
          {vkName(vk)}
        </option>
      ))}
    </select>
  );

  return (
    <div className="overlay">
      <div className="modal">
        <div className="modal-title">按键规则 · 主号按下 → 次窗口执行</div>
        <div className="tip" style={{ marginTop: 0 }}>
          表内的键由本规则接管: 主号按下时, 次窗口按「次号按」那一列的键执行。{"\n"}
          表外的键 (WASD 等) 仍按「键盘同步」原样全量转发, 同一个键不会重复。{"\n"}
          只在主窗口处于前台时生效; 次窗口仍需先校准, 含密码控件的窗口一律拒绝投递。
        </div>

        <div className="rule-wrap">
          <table className="win-table rule-table">
            <colgroup>
              <col style={{ width: 46 }} />
              <col />
              <col />
              <col style={{ width: 92 }} />
              <col style={{ width: 62 }} />
            </colgroup>
            <thead>
              <tr>
                <th>启用</th>
                <th>主号按</th>
                <th>次号按</th>
                <th>延迟(ms)</th>
                <th>连发</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r, i) => (
                <tr
                  key={i}
                  className={sel.has(i) ? "sel" : ""}
                  onClick={() => toggleSel(i)}
                >
                  <td style={{ textAlign: "center" }}>
                    <input
                      type="checkbox"
                      checked={r.on}
                      onClick={(e) => e.stopPropagation()}
                      onChange={(e) => patch(i, { on: e.target.checked })}
                    />
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>{keySelect(i, "src")}</td>
                  <td onClick={(e) => e.stopPropagation()}>{keySelect(i, "dst")}</td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <input
                      className="num"
                      type="number"
                      min={0}
                      max={RULE_MAX_DELAY_MS}
                      step={10}
                      value={r.delay}
                      onChange={(e) =>
                        patch(i, {
                          delay: Math.max(
                            0,
                            Math.min(RULE_MAX_DELAY_MS, Number(e.target.value) || 0)
                          ),
                        })
                      }
                    />
                  </td>
                  <td onClick={(e) => e.stopPropagation()}>
                    <input
                      className="num"
                      type="number"
                      min={1}
                      max={RULE_MAX_TIMES}
                      value={r.times}
                      onChange={(e) =>
                        patch(i, {
                          times: Math.max(
                            1,
                            Math.min(RULE_MAX_TIMES, Number(e.target.value) || 1)
                          ),
                        })
                      }
                    />
                  </td>
                </tr>
              ))}
              {rows.length === 0 && (
                <tr>
                  <td colSpan={5} className="empty">
                    没有规则 · 点「恢复默认」填入 1/2/3/4/5/TAB
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="row" style={{ marginTop: 10 }}>
          <button className="btn" onClick={addRow}>
            + 添加
          </button>
          <button className="btn" onClick={delRows}>
            删除选中
          </button>
          <button className="btn" onClick={reset}>
            恢复默认
          </button>
          <div className="spacer" />
          <button className="btn green" onClick={apply}>
            确定
          </button>
          <button className="btn" onClick={onClose}>
            取消
          </button>
        </div>
      </div>
    </div>
  );
}
