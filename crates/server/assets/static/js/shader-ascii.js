// shader-ascii.js — vanilla port of ~/.claude/wavefunk/ui_kits/_shared/ShaderAscii.jsx.
//
// Mounts on every <canvas data-shader-ascii> on the page. Reads config from
// data-* attributes. Renders a WebGL2 ASCII-like glyph field masked by a
// shape (text / image / primitive). Respects prefers-reduced-motion and
// gracefully degrades when WebGL2 is unavailable (the template provides
// a sibling <pre class="wf-ascii"> fallback).
//
// Public "API" (all optional except data-shader-ascii):
//   data-cell-scale        number of rows vertically (default 22)
//   data-shape-source      "text" | "image" | "primitive"  (default "text")
//   data-shape-text        string to rasterize when source = text
//   data-shape-image       URL to fetch when source = image (CORS required)
//   data-shape-primitive   "wordmark" | "circle" | "grid" | "wave"
//
// Mount timing: auto-mounts on DOMContentLoaded and re-mounts if the script
// is loaded after that event. Safe to re-run (keyed by data-shader-mounted).

(function () {
  "use strict";

  var VS_SRC = [
    "#version 300 es",
    "in vec2 a_pos;",
    "void main(){",
    "  gl_Position = vec4(a_pos, 0.0, 1.0);",
    "}"
  ].join("\n");

  var FS_SRC = [
    "#version 300 es",
    "precision highp float;",
    "out vec4 outColor;",
    "uniform vec2 uRes;",
    "uniform float uTime;",
    "uniform vec3 uAccent;",
    "uniform float uCellScale;",
    "uniform sampler2D uShapeMask;",
    "",
    "float hash21(vec2 p){ p = fract(p*vec2(123.34, 456.21)); p += dot(p, p+45.32); return fract(p.x*p.y); }",
    "float vnoise(vec2 p){",
    "  vec2 i = floor(p); vec2 f = fract(p);",
    "  float a = hash21(i);",
    "  float b = hash21(i+vec2(1,0));",
    "  float c = hash21(i+vec2(0,1));",
    "  float d = hash21(i+vec2(1,1));",
    "  vec2 u = f*f*(3.0-2.0*f);",
    "  return mix(mix(a,b,u.x), mix(c,d,u.x), u.y);",
    "}",
    "float fbm(vec2 p){",
    "  float v=0.0, a=0.5;",
    "  for(int i=0;i<4;i++){ v += a*vnoise(p); p*=2.02; a*=0.5; }",
    "  return v;",
    "}",
    "",
    "float glyph(int idx, vec2 uv){",
    "  vec2 c = uv - 0.5;",
    "  if(idx == 0) return 0.0;",
    "  if(idx == 1){ return step(length(c), 0.08); }",
    "  if(idx == 2){ return step(abs(c.y), 0.06) * step(abs(c.x), 0.28); }",
    "  if(idx == 3){ float a = step(abs(c.y - 0.12), 0.05) * step(abs(c.x), 0.28);",
    "                float b = step(abs(c.y + 0.12), 0.05) * step(abs(c.x), 0.28);",
    "                return max(a, b); }",
    "  if(idx == 4){ float h = step(abs(c.y), 0.06) * step(abs(c.x), 0.26);",
    "                float v = step(abs(c.x), 0.06) * step(abs(c.y), 0.26);",
    "                return max(h, v); }",
    "  if(idx == 5){ float r = length(c);",
    "                float ring = smoothstep(0.30, 0.26, r) * smoothstep(0.10, 0.14, r);",
    "                float ar = atan(c.y, c.x);",
    "                float spokes = step(0.5, abs(sin(ar*3.0)));",
    "                return max(ring, spokes*step(r, 0.28)); }",
    "  if(idx == 6){ float h1 = step(abs(c.y-0.12), 0.04) * step(abs(c.x), 0.30);",
    "                float h2 = step(abs(c.y+0.12), 0.04) * step(abs(c.x), 0.30);",
    "                float v1 = step(abs(c.x-0.12), 0.04) * step(abs(c.y), 0.30);",
    "                float v2 = step(abs(c.x+0.12), 0.04) * step(abs(c.y), 0.30);",
    "                return max(max(h1,h2), max(v1,v2)); }",
    "  if(idx == 7){ float ring = smoothstep(0.38, 0.34, length(c)) * smoothstep(0.18, 0.22, length(c));",
    "                float inner = step(length(c - vec2(0.06,0.0)), 0.07);",
    "                return max(ring, inner); }",
    "  return 0.0;",
    "}",
    "",
    "void main(){",
    "  vec2 frag = gl_FragCoord.xy;",
    "  float cellPx = max(8.0, uRes.y / uCellScale);",
    "  vec2 cellId = floor(frag / cellPx);",
    "  vec2 cellUv = fract(frag / cellPx);",
    "",
    "  vec2 np = cellId * 0.12 + vec2(uTime*0.08, uTime*0.05);",
    "  float n = fbm(np);",
    "  float edgeFade = smoothstep(0.0, 0.15, cellUv.x) * smoothstep(1.0, 0.85, cellUv.x)",
    "                 * smoothstep(0.0, 0.15, cellUv.y) * smoothstep(1.0, 0.85, cellUv.y);",
    "",
    "  vec2 centered = (cellId * cellPx + cellPx*0.5) / uRes - 0.5;",
    "  centered.x *= uRes.x / uRes.y;",
    "  float radial = 1.0 - smoothstep(0.30, 0.75, length(centered));",
    "",
    "  // Sample the shape mask at the center of this cell.",
    "  vec2 maskUv = (cellId * cellPx + cellPx*0.5) / uRes;",
    "  float mask = texture(uShapeMask, vec2(maskUv.x, 1.0 - maskUv.y)).a;",
    "",
    "  float density = n * radial * mask;",
    "",
    "  int idx = 0;",
    "  if(density > 0.72) idx = 7;",
    "  else if(density > 0.60) idx = 6;",
    "  else if(density > 0.50) idx = 5;",
    "  else if(density > 0.42) idx = 4;",
    "  else if(density > 0.35) idx = 3;",
    "  else if(density > 0.28) idx = 2;",
    "  else if(density > 0.22) idx = 1;",
    "",
    "  float g = glyph(idx, cellUv) * edgeFade;",
    "  float alpha = g * (0.55 + 0.35 * radial);",
    "  outColor = vec4(uAccent, alpha);",
    "}"
  ].join("\n");

  function parseHexRgb(s) {
    s = (s || "").trim();
    if (s.charAt(0) !== "#") return [1, 1, 1];
    var h = s.slice(1);
    var bytes;
    if (h.length === 3) {
      bytes = [parseInt(h[0] + h[0], 16), parseInt(h[1] + h[1], 16), parseInt(h[2] + h[2], 16)];
    } else if (h.length === 6) {
      bytes = [parseInt(h.slice(0, 2), 16), parseInt(h.slice(2, 4), 16), parseInt(h.slice(4, 6), 16)];
    } else {
      return [1, 1, 1];
    }
    return bytes.map(function (v) { return v / 255; });
  }

  function readAccent() {
    var css = getComputedStyle(document.documentElement);
    return parseHexRgb(css.getPropertyValue("--accent") || "#ffffff");
  }

  function compile(gl, type, src) {
    var s = gl.createShader(type);
    gl.shaderSource(s, src);
    gl.compileShader(s);
    if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) {
      console.error("shader-ascii:", gl.getShaderInfoLog(s));
      return null;
    }
    return s;
  }

  function hideCanvasShowFallback(canvas) {
    canvas.style.display = "none";
    var fallback = canvas.parentElement && canvas.parentElement.querySelector("pre.wf-ascii");
    if (fallback) fallback.style.display = "block";
  }

  // -- Shape-mask rasterizers --

  // Draw text as white-on-transparent into a 2D canvas, return ImageData.
  function rasterizeText(text, w, h) {
    var oc = document.createElement("canvas");
    oc.width = w; oc.height = h;
    var ctx = oc.getContext("2d");
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = "#ffffff";
    // Pick a font size that roughly fills the canvas horizontally.
    var fontSize = Math.floor(h * 0.65);
    ctx.font = "800 " + fontSize + "px 'Iosevka Aile', monospace";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    var upper = (text || "allowthem").toUpperCase();
    // Shrink font until it fits horizontally.
    while (ctx.measureText(upper).width > w * 0.9 && fontSize > 8) {
      fontSize -= 2;
      ctx.font = "800 " + fontSize + "px 'Iosevka Aile', monospace";
    }
    ctx.fillText(upper, w / 2, h / 2);
    return ctx.getImageData(0, 0, w, h);
  }

  // Primitive SDF drawn into a 2D canvas as white fill.
  function rasterizePrimitive(kind, w, h) {
    var oc = document.createElement("canvas");
    oc.width = w; oc.height = h;
    var ctx = oc.getContext("2d");
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = "#ffffff";
    ctx.strokeStyle = "#ffffff";
    if (kind === "circle") {
      var r = Math.min(w, h) * 0.35;
      ctx.beginPath();
      ctx.arc(w / 2, h / 2, r, 0, Math.PI * 2);
      ctx.fill();
    } else if (kind === "grid") {
      var step = Math.max(12, Math.floor(h / 16));
      ctx.lineWidth = 2;
      for (var x = 0; x <= w; x += step) {
        ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, h); ctx.stroke();
      }
      for (var y = 0; y <= h; y += step) {
        ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(w, y); ctx.stroke();
      }
    } else if (kind === "wave") {
      ctx.lineWidth = 4;
      for (var i = 0; i < 5; i++) {
        ctx.beginPath();
        for (var px = 0; px <= w; px += 4) {
          var t = px / w;
          var amp = h * 0.12;
          var yy = h / 2 + Math.sin(t * Math.PI * 4 + i) * amp + (i - 2) * h * 0.08;
          if (px === 0) ctx.moveTo(px, yy); else ctx.lineTo(px, yy);
        }
        ctx.stroke();
      }
    } else {
      // "wordmark" default — render "WAVE" centered.
      return rasterizeText("WAVE", w, h);
    }
    return ctx.getImageData(0, 0, w, h);
  }

  function imageBitmapToImageData(bitmap, w, h) {
    var oc = document.createElement("canvas");
    oc.width = w; oc.height = h;
    var ctx = oc.getContext("2d");
    ctx.clearRect(0, 0, w, h);
    // Fit-contain with center alignment.
    var scale = Math.min(w / bitmap.width, h / bitmap.height);
    var dw = bitmap.width * scale;
    var dh = bitmap.height * scale;
    ctx.drawImage(bitmap, (w - dw) / 2, (h - dh) / 2, dw, dh);
    return ctx.getImageData(0, 0, w, h);
  }

  function uploadMask(gl, tex, imageData) {
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.texImage2D(
      gl.TEXTURE_2D, 0, gl.RGBA,
      imageData.width, imageData.height, 0,
      gl.RGBA, gl.UNSIGNED_BYTE, imageData
    );
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
  }

  function init(canvas) {
    if (canvas.getAttribute("data-shader-mounted") === "1") return;
    canvas.setAttribute("data-shader-mounted", "1");

    var gl = canvas.getContext("webgl2", { antialias: false, alpha: true });
    if (!gl) { hideCanvasShowFallback(canvas); return; }

    var vs = compile(gl, gl.VERTEX_SHADER, VS_SRC);
    var fs = compile(gl, gl.FRAGMENT_SHADER, FS_SRC);
    if (!vs || !fs) { hideCanvasShowFallback(canvas); return; }

    var prog = gl.createProgram();
    gl.attachShader(prog, vs);
    gl.attachShader(prog, fs);
    gl.bindAttribLocation(prog, 0, "a_pos");
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) {
      console.error("shader-ascii: link failed", gl.getProgramInfoLog(prog));
      hideCanvasShowFallback(canvas);
      return;
    }

    var buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(
      gl.ARRAY_BUFFER,
      new Float32Array([-1, -1, 3, -1, -1, 3]),
      gl.STATIC_DRAW
    );

    var uRes = gl.getUniformLocation(prog, "uRes");
    var uTime = gl.getUniformLocation(prog, "uTime");
    var uAccent = gl.getUniformLocation(prog, "uAccent");
    var uCellScale = gl.getUniformLocation(prog, "uCellScale");
    var uShapeMask = gl.getUniformLocation(prog, "uShapeMask");

    var tex = gl.createTexture();
    // Default 1x1 transparent mask until the real one loads.
    gl.bindTexture(gl.TEXTURE_2D, tex);
    gl.texImage2D(
      gl.TEXTURE_2D, 0, gl.RGBA, 1, 1, 0, gl.RGBA, gl.UNSIGNED_BYTE,
      new Uint8Array([0, 0, 0, 0])
    );

    var cellScale = parseFloat(canvas.getAttribute("data-cell-scale") || "22");
    var source = canvas.getAttribute("data-shape-source") || "text";

    function resize() {
      var dpr = Math.min(window.devicePixelRatio || 1, 2);
      var r = canvas.getBoundingClientRect();
      canvas.width = Math.max(1, Math.floor(r.width * dpr));
      canvas.height = Math.max(1, Math.floor(r.height * dpr));
      refreshMask();
    }

    var maskW = 0;
    var maskH = 0;
    var lastImage = null;

    function refreshMask() {
      maskW = canvas.width;
      maskH = canvas.height;
      if (source === "text") {
        var t = canvas.getAttribute("data-shape-text")
          || canvas.getAttribute("aria-label")
          || "allowthem";
        uploadMask(gl, tex, rasterizeText(t, maskW, maskH));
      } else if (source === "primitive") {
        var kind = (canvas.getAttribute("data-shape-primitive") || "wordmark").toLowerCase();
        uploadMask(gl, tex, rasterizePrimitive(kind, maskW, maskH));
      } else if (source === "image") {
        if (lastImage) {
          uploadMask(gl, tex, imageBitmapToImageData(lastImage, maskW, maskH));
        }
      }
    }

    if (source === "image") {
      var url = canvas.getAttribute("data-shape-image");
      if (url) {
        fetch(url, { mode: "cors" })
          .then(function (r) { return r.blob(); })
          .then(function (b) { return createImageBitmap(b); })
          .then(function (bm) { lastImage = bm; refreshMask(); })
          .catch(function (e) { console.warn("shader-ascii image load failed:", e); });
      }
    }

    var ro = new ResizeObserver(resize);
    ro.observe(canvas);
    resize();

    var accent = readAccent();
    var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    var t0 = performance.now();
    var raf = 0;

    function frame(t) {
      gl.viewport(0, 0, canvas.width, canvas.height);
      gl.clearColor(0, 0, 0, 0);
      gl.clear(gl.COLOR_BUFFER_BIT);
      gl.enable(gl.BLEND);
      gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);

      gl.useProgram(prog);
      gl.bindBuffer(gl.ARRAY_BUFFER, buf);
      gl.enableVertexAttribArray(0);
      gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);

      gl.activeTexture(gl.TEXTURE0);
      gl.bindTexture(gl.TEXTURE_2D, tex);
      gl.uniform1i(uShapeMask, 0);
      gl.uniform2f(uRes, canvas.width, canvas.height);
      gl.uniform1f(uTime, reduced ? 0 : (t - t0) / 1000);
      gl.uniform3f(uAccent, accent[0], accent[1], accent[2]);
      gl.uniform1f(uCellScale, cellScale);

      gl.drawArrays(gl.TRIANGLES, 0, 3);
      if (!reduced) raf = requestAnimationFrame(frame);
    }
    if (reduced) frame(0);
    else raf = requestAnimationFrame(frame);
  }

  function mountAll() {
    var els = document.querySelectorAll("canvas[data-shader-ascii]");
    for (var i = 0; i < els.length; i++) init(els[i]);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", mountAll);
  } else {
    mountAll();
  }
})();
