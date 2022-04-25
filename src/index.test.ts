import { Sanitizer } from "./index";

// This file contains basic tests that validate the utility methods.
// For XSS attack sanitizer testing see xss.test.ts

// Sanitizes to {} or null (Node 16+ has some changes to Base data values)
const isNullOrEmptyObj = (result: any) => {
  return result === null || (result && typeof result === 'object' && Object.keys(result).length === 0)
}

describe("Sanitizer", () => {
  const allowedProtocols: string[] = [
    "http",
    "https",
    "mailto",
    "iform",
    "tel",
    "flow",
    "lfmobile",
    "arcgis-navigator",
    "arcgis-appstudio-player",
    "arcgis-survey123",
    "arcgis-collector",
    "arcgis-workforce",
    "arcgis-explorer",
    "arcgis-trek2there",
    "arcgis-quickcapture",
    "mspbi",
    "comgooglemaps",
    "pdfefile",
    "pdfehttp",
    "pdfehttps",
    "boxapp",
    "boxemm",
    "awb",
    "awbs",
    "gropen",
    "radarscope"
  ];

  test("creates the Sanitizer object and extends options appropriately", () => {
    // Test with no arguments
    const sanitizer1 = new Sanitizer();
    const defaultSanitizer1 = new Sanitizer();
    const defaultOptions1 = Object.create(
      defaultSanitizer1.arcgisFilterOptions
    );
    defaultOptions1.whiteList = defaultSanitizer1.arcgisWhiteList;
    expect(sanitizer1.xssFilterOptions).toEqual(defaultOptions1);

    // Extending the defaults
    const sanitizer2 = new Sanitizer(
      { allowCommentTag: false, whiteList: { blockquote: [] } },
      true
    );
    const defaultSanitizer2 = new Sanitizer();
    const filterOptions2 = Object.create(defaultSanitizer2.arcgisFilterOptions);
    filterOptions2.whiteList = defaultSanitizer2.arcgisWhiteList;
    filterOptions2.whiteList.blockquote = [];
    filterOptions2.allowCommentTag = false;
    expect(sanitizer2.xssFilterOptions).toEqual(filterOptions2);

    // Passing an empty whitelist
    // @ts-ignore
    const sanitizer3 = new Sanitizer({ whiteList: null }, true);
    const defaultSanitizer3 = new Sanitizer();
    const defaultOptions3 = Object.create(
      defaultSanitizer3.arcgisFilterOptions
    );
    defaultOptions3.whiteList = defaultSanitizer3.arcgisWhiteList;
    expect(sanitizer3.xssFilterOptions).toEqual(defaultOptions3);

    // Test overriding defaults
    const sanitizer4 = new Sanitizer({ whiteList: { a: [] } });
    expect(sanitizer4.xssFilterOptions).toEqual({ whiteList: { a: [] } });
  });

  test("sanitizes a value", () => {
    const sanitizer = new Sanitizer();

    // Numbers
    expect(sanitizer.sanitize(NaN)).toBe(null);
    expect(sanitizer.sanitize(Infinity)).toBe(null);
    expect(sanitizer.sanitize(123)).toBe(123);
    expect(sanitizer.sanitize(123)).toBe(123);

    // Boolean
    expect(sanitizer.sanitize(true)).toBe(true);
    expect(sanitizer.sanitize(false)).toBe(false);

    // Strings
    const basicString = "Hello World";
    const validHtml = 'Hello <a href="https://example.org">Link</a>';
    const invalidHtml =
      'Evil <img src="https://exmaple.org/myImg.jpg" onerror="alert(1)" />';
    const sanitizedInvalidHtml =
      'Evil <img src="https://exmaple.org/myImg.jpg" />';

    expect(sanitizer.sanitize(basicString)).toBe(basicString);
    expect(sanitizer.sanitize(validHtml)).toBe(validHtml);
    expect(sanitizer.sanitize(invalidHtml)).toBe(sanitizedInvalidHtml);

    // Built in Objects:https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects
    // Value Properties (Infinity and NanN defined in Numbers above)
    expect(sanitizer.sanitize(undefined)).toBe(null);
    expect(sanitizer.sanitize(null)).toBe(null);

    // Fundamental objects
    expect(sanitizer.sanitize(Object)).toBe(null);
    expect(sanitizer.sanitize(Function)).toBe(null);
    expect(sanitizer.sanitize(Boolean)).toBe(null);
    expect(sanitizer.sanitize(Symbol)).toBe(null);
    expect(sanitizer.sanitize(Error)).toBe(null);
    expect(sanitizer.sanitize(EvalError)).toBe(null);
    expect(sanitizer.sanitize(RangeError)).toBe(null);
    expect(sanitizer.sanitize(ReferenceError)).toBe(null);
    expect(sanitizer.sanitize(SyntaxError)).toBe(null);
    expect(sanitizer.sanitize(TypeError)).toBe(null);
    expect(sanitizer.sanitize(URIError)).toBe(null);

    // Number and dates
    expect(sanitizer.sanitize(Number)).toBe(null);
    expect(sanitizer.sanitize(Math)).toBe(null);
    expect(sanitizer.sanitize(Date)).toBe(null);
    expect(sanitizer.sanitize(new Date())).toBe(null);

    // Text processing
    expect(sanitizer.sanitize(String)).toBe(null);
    expect(sanitizer.sanitize(RegExp)).toBe(null);
    expect(sanitizer.sanitize(/\w+/)).toBe(null);

    // Indexed collections
    expect(sanitizer.sanitize(Array)).toBe(null);
    expect(sanitizer.sanitize(Int8Array)).toBe(null);
    expect(sanitizer.sanitize(Uint8Array)).toBe(null);
    expect(sanitizer.sanitize(Uint8ClampedArray)).toBe(null);
    expect(sanitizer.sanitize(Int16Array)).toBe(null);
    expect(sanitizer.sanitize(Uint16Array)).toBe(null);
    expect(sanitizer.sanitize(Int32Array)).toBe(null);
    expect(sanitizer.sanitize(Uint32Array)).toBe(null);
    expect(sanitizer.sanitize(Float32Array)).toBe(null);
    expect(sanitizer.sanitize(Float64Array)).toBe(null);

    // Keyed collections
    expect(sanitizer.sanitize(Map)).toBe(null);
    expect(sanitizer.sanitize(Set)).toBe(null);
    expect(sanitizer.sanitize(WeakMap)).toBe(null);
    expect(sanitizer.sanitize(WeakSet)).toBe(null);

    // Structured Data
    expect(sanitizer.sanitize(ArrayBuffer)).toBe(null);
    expect(sanitizer.sanitize(DataView)).toBe(null);
    expect(sanitizer.sanitize(JSON)).toBe(null);

    // Control abstraction objects
    expect(sanitizer.sanitize(Promise)).toBe(null);

    // Reflection
    expect(isNullOrEmptyObj(sanitizer.sanitize(Reflect))).toEqual(true);
    expect(sanitizer.sanitize(Proxy)).toBe(null);

    // Internationalization
    expect(isNullOrEmptyObj(sanitizer.sanitize(Intl))).toEqual(true);
    expect(sanitizer.sanitize(Intl.Collator)).toBe(null);
    expect(sanitizer.sanitize(Intl.DateTimeFormat)).toBe(null);
    expect(sanitizer.sanitize(Intl.NumberFormat)).toBe(null);

    // Others
    // @ts-ignore
    expect(sanitizer.sanitize(arguments)).toBe(null);
    expect(sanitizer.sanitize(() => "test")).toBe(null);
    expect(sanitizer.sanitize(new Error("test"))).toBe(null);
  });

  test("optionally allow undefined values to pass sanitizer", () => {
    const sanitizer = new Sanitizer();
    // tslint:disable-next-line:no-string-literal
    const _iterateOverObject = sanitizer["_iterateOverObject"];

    expect(sanitizer.sanitize(undefined)).toBe(null);
    expect(sanitizer.sanitize({ a: true, b: undefined })).toEqual({
      a: true,
      b: null
    });
    // @ts-ignore - will fail types check
    expect(_iterateOverObject(undefined, {})).toBe(null);

    expect(sanitizer.sanitize(undefined, { allowUndefined: true })).toBe(
      undefined
    );
    expect(
      sanitizer.sanitize({ a: true, b: undefined }, { allowUndefined: true })
    ).toEqual({ a: true, b: undefined });
    // @ts-ignore - will fail types check
    expect(_iterateOverObject(undefined, { allowUndefined: true })).toBe(
      undefined
    );
  });

  test("deeply sanitizes an object", () => {
    const sanitizer = new Sanitizer();

    // If object is clean, it return the exact same object;
    const cleanObj1 = {
      a: null,
      b: true,
      c: "clean string"
    };
    const result1 = sanitizer.sanitize(cleanObj1);
    expect(result1).toBe(cleanObj1);

    // Sanitizes dirty object
    const result2 = sanitizer.sanitize({
      a: 1,
      b: true,
      c: "clean string",
      d: 'Evil <img src="https://exmaple.org/myImg.jpg" onerror="alert(1)" />',
      e: [
        1,
        true,
        'Evil <img src="https://exmaple.org/myImg.jpg" onerror="alert(1)" />',
        ["inner", "array"]
      ],
      f: new Date()
    });
    const expected2 = {
      a: 1,
      b: true,
      c: "clean string",
      d: 'Evil <img src="https://exmaple.org/myImg.jpg" />',
      e: [
        1,
        true,
        'Evil <img src="https://exmaple.org/myImg.jpg" />',
        ["inner", "array"]
      ],
      f: null
    };
    expect(result2).toEqual(expected2);
  });

  test("checks if string is valid html", () => {
    const basicString = "Hello World";
    const validHtml = 'Hello <a href="https://example.org">Link</a>';
    const invalidHtml =
      'Evil <img src="https://exmaple.org/myImg.jpg" onerror="alert(1)" />';

    const sanitizer = new Sanitizer();

    expect(sanitizer.validate(basicString).isValid).toBe(true);
    expect(sanitizer.validate(validHtml).isValid).toBe(true);
    expect(sanitizer.validate(invalidHtml).isValid).toBe(false);
  });

  test("extends an object of array by concatenating arrays", () => {
    // tslint:disable-next-line:no-string-literal
    const _extendObjectOfArrays = new Sanitizer()["_extendObjectOfArrays"];

    const result = _extendObjectOfArrays([
      { a: [1, 2] },
      { a: [3, 4], b: [1, 2] },
      { b: [3, 4] }
    ]);

    expect(result).toEqual({ a: [1, 2, 3, 4], b: [1, 2, 3, 4] });
  });

  test("returns null of iteration fails", () => {
    // tslint:disable-next-line:no-string-literal
    const _iterateOverObject = new Sanitizer()["_iterateOverObject"];

    // Will fail because "this" is not defined
    expect(_iterateOverObject({ a: 1 })).toBe(null);
  });

  test("checks for allowed protocols", () => {
    const sanitizer = new Sanitizer();

    // Ensure the allowed protocols are not stripped out
    allowedProtocols.forEach((protocol: string) => {
      const anchor = `<a href="${protocol}://someurl.tld?param1=1&param2=2">Link</a>`;
      const image = `<img src="${protocol}://someurl.tld/path/to/image.svg">`;
      const audio = `<audio controls><source src="${protocol}://someurl.tld/path/to/audio/file.mp3"></audio>`;
      const video = `<video controls><source src="${protocol}://someurl.tld/path/to/video/file.mpeg"></video>`;
      const source = `<source src="${protocol}://someurl.tld/path/to/audio/file.mp3">`;
      expect(sanitizer.sanitize(anchor)).toBe(anchor);
      expect(sanitizer.sanitize(image)).toBe(image);
      expect(sanitizer.sanitize(audio)).toBe(audio);
      expect(sanitizer.sanitize(video)).toBe(video);
      expect(sanitizer.sanitize(source)).toBe(source);
    });
    // Ensure disallowed protocols are still disallowed and are sanitized
    const disallowedProtocols: string[] = ["ftp", "smb"];
    disallowedProtocols.forEach((protocol: string) => {
      const anchor = `<a href="${protocol}://someurl.tld?param1=1&param2=2">Link</a>`;
      const image = `<img src="${protocol}://someurl.tld/path/to/image.svg">`;
      const audio = `<audio controls><source src="${protocol}://someurl.tld/path/to/audio/file.mp3"></audio>`;
      const video = `<video controls><source src="${protocol}://someurl.tld/path/to/video/file.mpeg"></video>`;
      const source = `<source src=${protocol}://someurl.tld/path/to/audio/file.mp3">`;
      expect(sanitizer.sanitize(anchor)).toBe("<a href>Link</a>");
      expect(sanitizer.sanitize(image)).toBe("<img src>");
      expect(sanitizer.sanitize(audio)).toBe(
        "<audio controls><source src></audio>"
      );
      expect(sanitizer.sanitize(video)).toBe(
        "<video controls><source src></video>"
      );
      expect(sanitizer.sanitize(source)).toBe("<source src>");
    });

    // Check for protocols that don't include //, such as tel or mailto
    const tel = "tel:+1-111-111-1111";
    const mailto = "mailto:someuser@someurl.tld";

    // Check for caps and mixed case protocols
    const capsHttps = "HTTPS://someurl.tld?param1=1";
    const capsTel = "TEL:+1-111-111-1111";
    const mixedHttp = "hTTp://someurl.tld?param1=1";

    // Ensure we can still use "/" and "#" as anchor href values
    const root = "/";
    const hash = "#";
    const hashId = "#test";

    [tel, mailto, capsHttps, capsTel, mixedHttp, root, hash, hashId].forEach(
      (uri: string) => {
        const anchor = `<a href="${uri}">Link</a>`;
        const image = `<img src="${uri}">`;
        const audio = `<audio><source src="${uri}"></audio>`;
        const video = `<video><source src="${uri}"></audio>`;
        const source = `<source src="${uri}">`;
        expect(sanitizer.sanitize(anchor)).toBe(anchor);
        expect(sanitizer.sanitize(image)).toBe(image);
        expect(sanitizer.sanitize(audio)).toBe(audio);
        expect(sanitizer.sanitize(video)).toBe(video);
        expect(sanitizer.sanitize(source)).toBe(source);
      }
    );
  });

  test("sanitizes URLs", () => {
    const sanitizer = new Sanitizer();

    // Ensure allowed protocols are passed through untouched
    allowedProtocols.forEach((protocol: string) => {
      const url = `${protocol}://someurl.tld?param1=1&param2=2`;
      expect(sanitizer.sanitizeUrl(url)).toBe(url);
    });

    // Ensure disallowed protocols are still disallowed and are sanitized
    const disallowedProtocols: string[] = ["ftp", "smb"];
    disallowedProtocols.forEach((protocol: string) => {
      const url = `${protocol}://someurl.tld?param1=1&param2=2`;
      expect(sanitizer.sanitizeUrl(url)).toBe("");
    });

    // Check for protocols that don't include //, such as tel or mailto
    const tel = "tel:+1-111-111-1111";
    const mailto = "mailto:someuser@someurl.tld";

    // Check for caps and mixed case protocols
    const capsHttps = "HTTPS://someurl.tld?param1=1";
    const capsTel = "TEL:+1-111-111-1111";
    const mixedHttp = "hTTp://someurl.tld?param1=1";

    // Ensure we can still use "/" and "#" as anchor href values
    const root = "/";
    const hash = "#";
    const hashId = "#test";

    // Accept URLs without a protocol
    const withoutProtocol = "google.com";

    [tel, mailto, capsHttps, capsTel, mixedHttp, root, hash, hashId].forEach(
      (url: string) => {
        expect(sanitizer.sanitizeUrl(url)).toBe(url);
      }
    );
    expect(sanitizer.sanitizeUrl(withoutProtocol, { isProtocolRequired: false })).toBe(`https://${withoutProtocol}`);
    expect(sanitizer.sanitizeUrl(withoutProtocol, { isProtocolRequired: true })).toBe('');
  });
  
  test('sanitizes HTML attributes', () => {
    const sanitizer = new Sanitizer();
    // A pair of double quotes are encoded
    expect(sanitizer.sanitizeHTMLAttribute('button', 'aria-label', '"Text content"')).toBe('&quot;Text content&quot;');
    // Double quote is encoded
    expect(sanitizer.sanitizeHTMLAttribute('img', 'alt', '"')).toBe('&quot;');
    // Escaped double quotes are encoded
    expect(sanitizer.sanitizeHTMLAttribute('button', 'aria-label', '\"Text content\"')).toBe('&quot;Text content&quot;');
    // src with javascript URL should be removed
    expect(sanitizer.sanitizeHTMLAttribute('img', 'src', 'javascript:alert("xss")')).toBe('');    
    // href with javascript URL should be removed
    expect(sanitizer.sanitizeHTMLAttribute('a', 'href', 'javascript:alert("xss")')).toBe('');    
    // background with javascript URL should be removed
    expect(sanitizer.sanitizeHTMLAttribute('div', 'background', 'javascript:alert("xss")')).toBe('');
    // style with javascript URL should be removed
    expect(sanitizer.sanitizeHTMLAttribute('div', 'style', 'background-image:url("javascript:alert(\"xss\")")')).toBe('');                
    // safe styles should be allowed
    expect(sanitizer.sanitizeHTMLAttribute('div', 'style', 'color:red;font-size:12px;')).toBe('color:red; font-size:12px;');
    // custom filter removes style value
    expect(sanitizer.sanitizeHTMLAttribute('div', 'style', 'color:red;', { process: (value: string) => value.indexOf('color') !== -1 ? '' : value })).toBe('');                
    // custom filter still disallows javascript URLs
    expect(sanitizer.sanitizeHTMLAttribute('div', 'style', 'background-image:url("javascript:alert(\"xss\")"', { process: (value: string) => value })).toBe('');        
    // attempt to prematurely close the HTML element and inject script tag should be thwarted by encoding
    expect(sanitizer.sanitizeHTMLAttribute('img', 'alt', '"><script>alert("Text content")</script>')).toBe('&quot;&gt;&lt;script&gt;alert(&quot;Text content&quot;)&lt;/script&gt;')    
    
    const customSanitizer = new Sanitizer({
      safeAttrValue: (tag, name, value, cssFilter) => {        
        if (tag === 'div' && name === 'data-something') {
          return '';
        }

        // this is only shown for testing; in practice a custom safeAttrValue needs to escape input 
        // (by calling `xss.safeAttrValue()` here) instead of returning it blindly
        return value;
      }      
    });    
    // Removes attributes disallowed by custom safeAttrValue  
    expect(customSanitizer.sanitizeHTMLAttribute('div', 'data-something', 'Content')).toBe('');
    // Preserves attributes allowed by custom safeAttrValue  
    expect(customSanitizer.sanitizeHTMLAttribute('img', 'alt', 'A picture')).toBe('A picture');
    
    // no custom safeAttrValue
    const anotherCustomSanitizer = new Sanitizer({});    
    // basic quote escaping
    expect(anotherCustomSanitizer.sanitizeHTMLAttribute('button', 'aria-label', '"Text content"')).toBe('&quot;Text content&quot;');
    // src with javascript URL should be removed
    expect(anotherCustomSanitizer.sanitizeHTMLAttribute('img', 'src', 'javascript:alert("xss")')).toBe('');    
    // href with javascript URL should be removed
    expect(anotherCustomSanitizer.sanitizeHTMLAttribute('a', 'href', 'javascript:alert("xss")')).toBe(''); 
    // custom filter removes style value
    expect(anotherCustomSanitizer.sanitizeHTMLAttribute('div', 'style', 'color:red;', { process: (value: string) => value.indexOf('color') !== -1 ? '' : value })).toBe('');                
    // custom filter still disallows javascript URLs
    expect(anotherCustomSanitizer.sanitizeHTMLAttribute('div', 'style', 'background-image:url("javascript:alert(\"xss\")"', { process: (value: string) => value })).toBe('');               
  });

  test("check for some of the allowed tags and attributes", () => {
    const u = "<u>String</u>";
    const hr = "<hr>";
    const abbr = `<abbr title="Cascading Style Sheets">CSS</abbr>`;
    const ol = "<ol><li>List Item 1</li><li>List Item 2</li></ol>";
    const safeDiv = '<div style="display:none;">Text content</div>';
    const unsafeDiv = '<div onerror="alert(1)">Text content</div>';
    const strippedDiv = "<div>Text content</div>";
    const audio = `<audio controls><source src="http://someurl.tld/path/to/audio/file.mp3" type="audio/mpeg"></audio>`;
    const video = `<video controls><source src="http://someurl.tld/path/to/video/file.mpeg" type="video/mpeg"></video>`;
    const stripAudioSrc = `<audio controls src="http://someurl.tld/path/to/audio/file.mp3">`;
    const stripVideoSrc = `<video controls src="http://someurl.tld/path/to/video/file.mpeg">`;
    const strippedAudioSrc = "<audio controls>";
    const strippedVideoSrc = "<video controls>";
    const fontFace = `<font face="Arial">Text content</font>`;
    const figure = `<figure style="background-color:blue;background-image:url("javascript:alert(\"xss\")";" onerror="alert(1)" onclick="javascript:alert(\"xss\")"><figcaption style="background-color:red;background-image:url("javascript:alert(\"xss\")";" onerror="alert(1)" onclick="javascript:alert(\"xss\")">Figure Caption</figcaption></figure>`;
    const elementsWithStyle = ["a", "img", "span", "div", "font", "table", "tr", "th", "td", "p", "dd", "dl", "dt", "h1", "h2", "h3", "h4", "h5", "h6", "sub", "sup"];

    const sanitizer = new Sanitizer();

    expect(sanitizer.sanitize(u)).toBe(u);
    expect(sanitizer.sanitize(hr)).toBe(hr);
    expect(sanitizer.sanitize(abbr)).toBe(abbr);
    expect(sanitizer.sanitize(ol)).toBe(ol);
    expect(sanitizer.sanitize(safeDiv)).toBe(safeDiv);
    expect(sanitizer.sanitize(unsafeDiv)).toBe(strippedDiv);
    expect(sanitizer.sanitize(audio)).toBe(audio);
    expect(sanitizer.sanitize(stripAudioSrc)).toBe(strippedAudioSrc);
    expect(sanitizer.sanitize(video)).toBe(video);
    expect(sanitizer.sanitize(stripVideoSrc)).toBe(strippedVideoSrc);
    expect(sanitizer.sanitize(fontFace)).toBe(fontFace);
    expect(sanitizer.sanitize(figure)).toBe(
      `<figure style="background-color:blue;"><figcaption style="background-color:red;">Figure Caption</figcaption></figure>`
    );
    elementsWithStyle.forEach((element) => {
      expect(sanitizer.sanitize(
        `<${element} style="background-color:blue;background-image:url("javascript:alert(\"xss\")";" onerror="alert(1)" onclick="javascript:alert(\"xss\")">Text content</${element}>`
      )).toBe(
        `<${element} style="background-color:blue;">Text content</${element}>`
      );
    });
  });

  test("trims a string", () => {
    // tslint:disable-next-line:no-string-literal
    const _trim = new Sanitizer()["_trim"];

    const str = " \tString\n\r \t";
    const trimmedString = "String";

    // Save String.prototype.trim
    const trimPrototype = String.prototype.trim;

    // Remove String.prototype.trim for regex path tests
    // @ts-ignore
    delete String.prototype.trim;

    // Using regex
    expect(_trim(str)).toBe(trimmedString);
    expect(_trim(trimmedString)).toBe(trimmedString);

    // Return trim to String prototype
    String.prototype.trim = trimPrototype;

    // Using String.prototype.trim
    expect(_trim(str)).toBe(trimmedString);
    expect(_trim(trimmedString)).toBe(trimmedString);
  });

  test("encodes HTML", () => {
    const sanitizer = new Sanitizer();
    const entities = ["&", "<", ">", '"', "'", "/"];
    const mappedEntities = ["&#x38;", "&#x3C;", "&#x3E;", "&#x22;", "&#x27;", "&#x2F;"];
    const html = `<a href="https://someurl.tld">Link '1'</a> &middot; <a href="https://someurl.tld/path1">Link '2'</a>`;
    const encoded = `&#x3C;a href=&#x22;https:&#x2F;&#x2F;someurl.tld&#x22;&#x3E;Link &#x27;1&#x27;&#x3C;&#x2F;a&#x3E; &#x38;middot; &#x3C;a href=&#x22;https:&#x2F;&#x2F;someurl.tld&#x2F;path1&#x22;&#x3E;Link &#x27;2&#x27;&#x3C;&#x2F;a&#x3E;`;
    const text = "This is plain text with no encoding necessary.";

    // check all characters encoded by this method
    entities.forEach((entity: string, idx: number) => {
      expect(sanitizer.encodeHTML(entity)).toBe(mappedEntities[idx]);
    });

    // ensure HTML string is encoded
    expect(sanitizer.encodeHTML(html)).toBe(encoded);

    // Ensure text with none of the characters that are encoded is not transfored
    expect(sanitizer.encodeHTML(text)).toBe(text);
  });

  test("encodes HTML attribute values", () => {
    const sanitizer = new Sanitizer();
    const url = "https://someurl.tld/path1?f=json&ts=123002398483";
    const alert = "javascript:alert(document.cookie)";
    const encodedUrl =
      "https&#x3a;&#x2f;&#x2f;someurl&#x2e;tld&#x2f;path1&#x3f;f&#x3d;json&#x26;ts&#x3d;123002398483";
    const encodedAlert =
      "javascript&#x3a;alert&#x28;document&#x2e;cookie&#x29;";

    // Ensure alphanumeric characters are not encoded
    const alphanumeric =
      "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ".split(
        ""
      );
    alphanumeric.forEach((char: string) => {
      expect(sanitizer.encodeAttrValue(char)).toBe(char);
    });

    // Ensure non-alphanumeric characters are encoded between 0x00 and 0xFF
    const alphanumericRE = /^[a-zA-Z0-9]$/;
    for (let charCode = 0; charCode < 256; ++charCode) {
      const char = String.fromCharCode(charCode);
      if (!alphanumericRE.test(char)) {
        const hexCharCode = charCode.toString(16);
        expect(sanitizer.encodeAttrValue(char)).toBe(`&#x${hexCharCode};`);
      }
    }

    // Ensure " and ' are encoded correctly
    expect(sanitizer.encodeAttrValue('"')).toBe("&#x22;");
    expect(sanitizer.encodeAttrValue("'")).toBe("&#x27;");

    // Ensure expected encoding happens for a sample URL
    expect(sanitizer.encodeAttrValue(url)).toBe(encodedUrl);

    // Ensure expected encoding happens for a JavaScript alert statement
    expect(sanitizer.encodeAttrValue(alert)).toBe(encodedAlert);
  });

});
