const path = require('path');
const pkg = require('./package');

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
    output: {
      filename: `${pkg.name.replace('@esri/', '')}${
        argv.mode === 'production' ? '.min' : ''
      }.js`,
      path: path.resolve(__dirname, 'dist/umd')
    }
  };
};
