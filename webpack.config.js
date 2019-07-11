const path = require('path');
const pkg = require('./package');
const webpack = require('webpack');

module.exports = (env, argv) => {
  return {
    entry: './src/index.ts',
    devtool: 'source-map',
    module: {
      rules: [
        {
          test: /\.tsx?$/,
          use: 'ts-loader',
          exclude: /node_modules/
        }
      ]
    },
    resolve: {
      extensions: ['.tsx', '.ts', '.js']
    },
    plugins: [
      new webpack.BannerPlugin({
        banner:
          `${pkg.name} - v${pkg.version} - ${new Date().toString()}` +
          '\n' +
          `Copyright (c) ${new Date().getFullYear()} - Environmental Systems Research Institute, Inc.` +
          '\n' +
          `${pkg.license}` +
          '\n\n' +
          `js-xss` +
          '\n' +
          `Copyright (c) 2012-2017 Zongmin Lei(雷宗民) <leizongmin@gmail.com>` +
          '\n' +
          `http://ucdok.com` +
          '\n' +
          `MIT License, see https://github.com/leizongmin/js-xss/blob/master/LICENSE for details` +
          '\n\n' +
          `Lodash/isPlainObject` +
          '\n' +
          `Copyright (c) JS Foundation and other contributors <https://js.foundation/>` +
          '\n' +
          `MIT License, see https://raw.githubusercontent.com/lodash/lodash/4.17.10-npm/LICENSE for details`
      })
    ],
    output: {
      filename: `${pkg.name.replace('@esri/', '')}${
        argv.mode === 'production' ? '.min' : ''
      }.js`,
      path: path.resolve(__dirname, 'dist/umd'),
      globalObject: 'this',
      library: 'Sanitizer',
      libraryExport: 'Sanitizer',
      libraryTarget: 'umd'
    }
  };
};
