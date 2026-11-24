package web

import "embed"

// Assets 嵌入全部前端 HTML / CSS / JS 资源，实现单文件零外部静态依赖部署。
//
//go:embed index.html styles.css dashboard.js portal.html portal.js
var Assets embed.FS
