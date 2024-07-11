var webpack = require("webpack"),
  path = require("path"),
  CopyWebpackPlugin = require("copy-webpack-plugin"),
  TerserPlugin = require("terser-webpack-plugin");
var { CleanWebpackPlugin } = require("clean-webpack-plugin");

const ASSET_PATH = process.env.ASSET_PATH || "/";

var options = {
  mode: process.env.NODE_ENV || "development",
  ignoreWarnings: [
    /Circular dependency between chunks with runtime/,
    /ResizeObserver loop completed with undelivered notifications/
  ],
  entry: {
    popup: path.join(__dirname, "src/popup.js"),
    background: path.join(__dirname, "src/background.js"),
    content: path.join(__dirname, "src/content.js"),
    offscreen: path.join(__dirname, "src/offscreen.js"),
  },
  output: {
    filename: "[name].js",
    path: path.resolve(__dirname, "build"),
    clean: true,
    publicPath: ASSET_PATH,
  },
  module: {
    rules: [
      {
        test: /\.html$/,
        loader: "html-loader",
        exclude: /node_modules/,
      },
      {
        test: /\.(js|jsx)$/,
        use: [
          {
            loader: "source-map-loader",
          },
          {
            loader: require.resolve("babel-loader"),
          },
        ],
        exclude: /node_modules/,
      },
    ],
  },
  plugins: [
    new CleanWebpackPlugin({ verbose: false }),
    new webpack.ProgressPlugin(),
    // expose and write the allowed env vars on the compiled bundle
    new webpack.EnvironmentPlugin(["NODE_ENV"]),
    new CopyWebpackPlugin({
      patterns: [
        "src/manifest.json",
        "src/offscreen.html",
        "src/popup.html",
        "src/popup.css",
        {
            context: __dirname + '/src',
            from: "icons/**",
            to: path.join(__dirname, "build"),
        },
        {
            context: __dirname + '/src',
            from: "utils/**",
            to: path.join(__dirname, "build"),
        },
        {
            from: "node_modules/tlsn-js/build",
            to: path.join(__dirname, "build"),
            force: true,
        },
      ],
    }),
    new webpack.ProvidePlugin({
      Buffer: ['buffer', 'Buffer'],
    }),
  ].filter(Boolean),
  infrastructureLogging: {
    level: "info",
  },
  // Required by wasm-bindgen-rayon, in order to use SharedArrayBuffer on the Web
  // Ref:
  //  - https://github.com/RReverser/wasm-bindgen-rayon?tab=readme-ov-file#setting-up
  //  - https://web.dev/articles/coop-coep
  devServer: {
    headers: {
      'Cross-Origin-Embedder-Policy': 'require-corp',
      'Cross-Origin-Opener-Policy': 'same-origin',
    }
  },
};

if (process.env.NODE_ENV === "development") {
  options.devtool = "cheap-module-source-map";
} else {
  options.optimization = {
    minimize: true,
    minimizer: [
      new TerserPlugin({
        extractComments: false,
      }),
    ],
  };
}

module.exports = options;
