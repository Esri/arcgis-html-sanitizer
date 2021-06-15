import commonjs from "@rollup/plugin-commonjs";
import replace from "@rollup/plugin-replace";
import resolve from "@rollup/plugin-node-resolve";
import typescript from "@rollup/plugin-typescript";
import { terser } from "rollup-plugin-terser";

import pkg from "./package.json";

const banner = `/*!
 * ${pkg.name} - v${pkg.version} - ${new Date().toString()}
 * Copyright (c) ${new Date().getFullYear()} - Environmental Systems Research Institute, Inc.
 * ${pkg.license}
 * 
 * js-xss
 * Copyright (c) 2012-2017 Zongmin Lei(雷宗民) <leizongmin@gmail.com>
 * http://ucdok.com
 * MIT License, see https://github.com/leizongmin/js-xss/blob/master/LICENSE for details
 * 
 * Lodash/isPlainObject
 * Copyright (c) JS Foundation and other contributors <https://js.foundation/>
 * MIT License, see https://raw.githubusercontent.com/lodash/lodash/4.17.10-npm/LICENSE for details
 */`;

const createBaseConfig = (format) => ({
  input: format === "umd" ? "src/default.ts" : "src/index.ts",
  plugins: [
    replace({
      // prevent the creation of filterCSS and filterXSS globals
      "typeof window": "typeof undefined",
      "include": ["node_modules/cssfilter/**", "node_modules/xss/**"],
      "preventAssignment": true
    }),
    format === "esm" && {
      generateBundle() {
        this.emitFile({ type: "asset", fileName: "package.json", source: `{ "type": "module" }` });
      }
    },
    resolve(),
    commonjs(),
    typescript()
  ]
});

export default [
  {
    ...createBaseConfig("cjs"),
    external: Object.keys(pkg.dependencies),
    output: [{ banner, format: "cjs", file: pkg.main, exports: "named" }]
  },
  {
    ...createBaseConfig("esm"),
    output: [
      { banner, format: "esm", file: pkg.module },
      { banner, format: "esm", file: pkg.module.replace(".js", ".min.js"), plugins: [terser()] }
    ]
  },
  {
    ...createBaseConfig("umd"),
    output: [
      {
        banner,
        format: "umd",
        file: `dist/umd/${pkg.name.replace("@esri/", "")}.js`,
        name: "Sanitizer"
      },
      {
        banner,
        format: "umd",
        file: `dist/umd/${pkg.name.replace("@esri/", "")}.min.js`,
        name: "Sanitizer",
        plugins: [terser()]
      }
    ]
  }
];
