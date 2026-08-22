# FusionWeb Frontend

FusionWeb 当前前端是基于 Next.js、React、TypeScript 和 Tailwind CSS 的单页管理界面。旧 Vue 文件已归档到 `legacy/vue-reference`，仅作为历史功能对照参考，不参与 Next.js 构建。

## 技术栈

- Next.js 15
- React 19
- TypeScript
- Tailwind CSS 4
- Radix UI
- TanStack Query / Table / Virtual
- CodeMirror
- Lucide React

## 开发启动

```powershell
cd C:\Codex\FusionWeb\frontend
npm install
npm run dev
```

默认开发地址：

```text
http://localhost:5173/
```

## 常用命令

```powershell
npm run typecheck
npm run build
```

`npm run build` 会先执行 TypeScript 检查，再运行 Next.js 静态导出，并把 `out` 复制到 `dist`。

## 与后端联调

前端接口封装位于：

```text
C:\Codex\FusionWeb\frontend\src\lib
```

登录会从后端获取 SM2 公钥。公钥接口不可用时，前端会阻止登录并提示错误，不会降级发送明文用户名或密码。

## 打包

推荐使用根目录脚本统一打包：

```powershell
cd C:\Codex\FusionWeb\scripts
powershell -NoProfile -ExecutionPolicy Bypass -File .\build-all.ps1
```

该脚本会处理前端依赖、前端构建和 Go 后端/桌面程序构建。

## 目录说明

- `src/app`：Next.js 入口。
- `src/components/fusion`：当前 React 功能页面。
- `src/components/ui.tsx`：通用 UI 组件。
- `src/lib`：接口、加密、工具函数。
- `public`：静态资源。
- `dist`：生产静态导出产物。
- `legacy/vue-reference`：旧 Vue 版本参考文件，不参与当前构建。

## 已知工程项

- 旧 Vue 源码保留在 `legacy/vue-reference` 作为功能对照参考，但 Vue/Vite 依赖已从当前包清单移除。
- 当前生产构建会执行 TypeScript 检查，并由 Next.js 执行 lint/type 校验。
