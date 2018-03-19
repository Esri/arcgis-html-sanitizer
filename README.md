# @esri/arcgis-html-sanitizer

This utility is a simple wrapper around the [js-xss](https://github.com/leizongmin/js-xss) library that will configure `js-xss` to sanitizes strings according to the [ArcGIS Supported HTML spec](https://doc.arcgis.com/en/arcgis-online/reference/supported-html.htm). It also
includes a few additional helper methods to make easier to validate strings and
prevent XSS attacks.

## Table of Contents

* [Why js-xss?\*\*](#why-js-xss)
* [Installation](#installation)
* [Usage](#usage)
* [Issues](#issues)
* [Versioning](#versioning)
* [Contributing](#contributing)
* [License](#license)

### Why [js-xss](https://github.com/leizongmin/js-xss)?\*\*

js-xss is lightweight (5.5k gzipped)
library that is license under the [MIT open source license](https://github.com/leizongmin/js-xss#license). It is also highly customizable
and works well in NodeJS applications and in the browser.

### Installation

Using npm:

```sh
npm install --save @esri/arcgis-html-sanitizer
```

Using Yarn:

```sh
yarn add @esri/arcgis-html-sanitizer
```

### Usage

#### Import

ES Modules

```js
import { Sanitizer } from '@esri/arcgis-html-sanitizer';
```

CommonJS

```js
const Sanitizer = require('@esri/arcgis-html-sanitizer').Sanitizer;
```

AMD (Use UMD version in ./dist/umd folder)

```js
define(['path/to/dist/umd/arcgis-html-sanitizer'], function(Sanitizer) {
  ...
})
```

Load as script tag

```html
<!-- Local -->
<script src="path/to/arcgis-html-sanitizer.min.js"></script>

<!-- CDN -->
<script src="https://cdn.jsdelivr.net/npm/@esri/arcgis-html-sanitizer@0.1.0/dist/umd/arcgis-html-sanitizer.min.js"></script>
```

#### Basic Usage

```js
// Instantiate a new Sanitizer object
const sanitizer = new Sanitizer();

// Check if a string contains invalid HTML
const isValid = sanitizer.isValidHtml(
  '<img src="https://example.com/fake-image.jpg" onerror="alert(1);" />'
);
// isValid => false

const sanitizedHtml = sanitizer.sanitize(
  '<img src="https://example.com/fake-image.jpg" onerror="alert(1);" />'
);
// sanitizedHtml => <img src="https://example.com/fake-image.jpg" />
```

#### Customizing Filter Options

Override the default XSS filter options by passing a valid js-css options object as the first parameter of the constructor. Options available here: https://github.com/leizongmin/js-xss#custom-filter-rules.

You can also extend the default options instead of overriding them by passing `true` as the second parameter of the constructor. When extending
the filter options `whiteList`, the attribute arrays will automatically
be concatenated to the defaults instead of replacing them.

```js
const customSanitizer = new Sanitizer({
  whiteList: {
    a: ['data-example']
  },
  escapeHtml: function () {
    ...
  }
}, true /* extend defaults */);
```

### Issues

If something isn't working the way you expected, please take a look at [previously logged issues](https://github.com/Esri/arcgis-html-sanitizer/issues) first. Have you found a new bug? Want to request a new feature? We'd [**love**](https://github.com/Esri/arcgis-html-sanitizer/issues/new) to hear from you.

If you're looking for help you can also post issues on [GIS Stackexchange](http://gis.stackexchange.com/questions/ask?tags=esri-oss).

### Versioning

For transparency into the release cycle and in striving to maintain backward compatibility, @esri/arcgis-rest-js is maintained under Semantic Versioning guidelines and will adhere to these rules whenever possible.

For more information on SemVer, please visit <http://semver.org/>.

### Contributing

Esri welcomes contributions from anyone and everyone. Please see our [guidelines for contributing](https://github.com/esri/contributing).

### License

Copyright 2018 Esri

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

> http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

A copy of the license is available in the repository's [LICENSE](./LICENSE) file.
