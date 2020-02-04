import { Sanitizer } from "./index";

// Rollup's UMD build will directly return the default export.
// This is a workaround for Rollup not having a config property like Webpack's: libraryExport: 'Sanitizer'
export default Sanitizer;
