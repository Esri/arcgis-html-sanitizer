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
          `${pkg.license}` + '\n' +
`js-xss
Copyright (c) 2012-2017 Zongmin Lei(雷宗民) <leizongmin@gmail.com>
http://ucdok.com
MIT License, see https://github.com/leizongmin/js-xss/blob/master/LICENSE for details`
      })
    ],
    output: {
      filename: `${pkg.name.replace('@esri/', '')}${
        argv.mode === 'production' ? '.min' : ''
      }.js`,
      path: path.resolve(__dirname, 'dist/umd'),
      library: 'Sanitizer',
      libraryExport: 'Sanitizer',
      libraryTarget: 'umd'
    }
  };
};
