# 第三方来源与说明

本文件用于记录本仓库中**非完全原创**内容的来源、已知许可信息与本仓库所做修改。

---

## 1) 导出的 CTF 专项 skill 集

涉及目录：

- `ctf-ai-ml`
- `ctf-crypto`
- `ctf-forensics`
- `ctf-malware`
- `ctf-misc`
- `ctf-osint`
- `ctf-pwn`
- `ctf-reverse`
- `ctf-web`
- `ctf-writeup`
- `solve-challenge`

- Source: `https://github.com/ljagiello/ctf-skills`
- Original path: 对应上游仓库中的 CTF skill 目录（请按需要进一步逐项精确映射）
- Original author: `ljagiello` 与该仓库贡献者
- Original license: 当前导出副本中各 `SKILL.md` frontmatter 标注为 `MIT`；公开发布前建议再与上游仓库实际许可证核对一次
- Modified by: `asdfgh1445`
- Notes: exported into local Codex skill store and then re-exported into this repository; localized frontmatter; added Chinese repository docs; added installation/validation scripts; added GitHub templates and CI; integrated with `ctf-beginner-hub` and `ctf-super-hub`

---

## 2) `brainstorming` skill

涉及目录：

- `brainstorming`

- Source: `https://github.com/foryourhealth111-pixel/Vibe-Skills`
- Original path: `bundled/skills/brainstorming`
- Original author: 以 `Vibe-Skills` 仓库维护者与贡献者记录为准
- Original license: `Apache License 2.0`
- Modified by: `asdfgh1445`
- Notes: exported into local Codex skill store and then re-exported into this repository; preserved trigger name `brainstorming`; localized frontmatter and repository-level docs; retained supporting files such as `visual-companion.md`, `spec-document-reviewer-prompt.md`, `scripts/*`, `agents/*`

### 第三方许可证副本

已附带 `Vibe-Skills` 的许可证副本：

- `third_party/Vibe-Skills-LICENSE`

---

## 3) 本仓库新增/原创整合内容

以下内容为本仓库在导出基础上的新增或重写内容：

- `ctf-super-hub/`
- `ctf-beginner-hub/references/*`
- `README.md`
- `START-HERE.md`
- `SKILL-INDEX.md`
- `docs/*`
- `.github/*`
- `scripts/validate_skills.py`
- `scripts/install_ctf_tools.sh`（整合与补充版）
- `install-to-codex.sh`
- 仓库级 `LICENSE`、`SECURITY.md`、`CONTRIBUTING.md`、`CODE_OF_CONDUCT.md`

- Source: 本仓库整理与新增内容
- Original author: `asdfgh1445`
- Original license: `MIT`（以本仓库 `LICENSE` 为准）
- Modified by: `asdfgh1445`
- Notes: added super-hub routing layer, beginner-oriented docs, publishing files, CI validation, and Chinese localization for names/descriptions while keeping trigger names unchanged

---

## 发布前建议

如果你想把风险再降一点，建议在正式公开前再补两类信息：

1. 为 `ctf-ai-ml` ~ `solve-challenge` 补更精确的**上游目录映射**  
2. 在上游仓库中再人工核对一次**最终许可证文本**与**作者/贡献者归属**


---

## 4) Strix 增强能力子集

涉及目录：

- `strix-*`
- `strix-beginner-hub`

- Source: `/Users/zhaomingzhe/.codex/skills/strix-*`
- Original author: 未在导出内容中统一标识；请以你本地 Strix 来源为准
- Original license: 请按 Strix 实际上游来源补充确认
- Modified by: `asdfgh1445`
- Notes: exported only a beginner-friendly subset; used as an enhancement layer for the existing CTF bundle rather than replacing the original two-mode entry structure
