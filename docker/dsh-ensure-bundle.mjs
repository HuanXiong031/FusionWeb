// 确保 DSH profile 的 bundle 列表包含指定插件（幂等）。
// 用法: node dsh-ensure-bundle.mjs <profile 的 package.json> <bundle 名> [bundle 路径]
import fs from 'node:fs'

const [pkgPath, bundleName, bundlePath] = process.argv.slice(2)
if (!pkgPath || !bundleName) {
  console.error('usage: dsh-ensure-bundle.mjs <package.json> <bundle> [path]')
  process.exit(2)
}

let pkg
try {
  pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf8'))
} catch (err) {
  console.error(`无法读取 ${pkgPath}: ${err?.message || err}`)
  process.exit(1)
}

pkg.dsh = pkg.dsh || {}
pkg.dsh.profile = pkg.dsh.profile || {}
const bundles = Array.isArray(pkg.dsh.profile.bundles) ? pkg.dsh.profile.bundles : []

let changed = false
if (!bundles.includes(bundleName)) {
  bundles.push(bundleName)
  changed = true
}
pkg.dsh.profile.bundles = bundles

if (bundlePath) {
  pkg.dependencies = pkg.dependencies || {}
  const dep = `file:${bundlePath}`
  if (pkg.dependencies[bundleName] !== dep) {
    pkg.dependencies[bundleName] = dep
    changed = true
  }
}

if (changed) {
  fs.writeFileSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`)
  console.log(`已把 ${bundleName} 写入 profile bundles`)
} else {
  console.log(`${bundleName} 已在 profile bundles 中`)
}
