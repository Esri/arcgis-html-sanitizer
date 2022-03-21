/* Copyright (c) 2020 Environmental Systems Research Institute, Inc.
 * Apache-2.0
 *
 * js-xss
 * Copyright (c) 2012-2018 Zongmin Lei(雷宗民) <leizongmin@gmail.com>
 * http://ucdok.com
 * The MIT License, see
 * https://github.com/leizongmin/js-xss/blob/master/LICENSE for details
 *
 * Lodash/isPlainObject
 * Copyright (c) JS Foundation and other contributors <https://js.foundation/>
 * MIT License, see https://raw.githubusercontent.com/lodash/lodash/4.17.10-npm/LICENSE for details
 * */
import isPlainObject from "lodash.isplainobject";
import * as xss from "xss";

/**
 * The response from the validate method
 *
 * @export
 * @interface IValidationResponse
 */
export interface IValidationResponse {
  isValid: boolean;
  sanitized: any;
}

export interface IWhiteList extends XSS.IWhiteList {
  source?: string[];
}

/** Options to apply to sanitize method */
export interface ISanitizeOptions {
  /* Don't convert undefined to null */
  allowUndefined?: boolean;
}

/**
 * The Sanitizer Class
 *
 * @export
 * @class Sanitizer
 */
export class Sanitizer {
  // Supported HTML Spec: https://doc.arcgis.com/en/arcgis-online/reference/supported-html.htm
  public readonly arcgisWhiteList: IWhiteList = {
    a: ["href", "style", "target"],
    abbr: ["title"],
    audio: ["autoplay", "controls", "loop", "muted", "preload"],
    b: [],
    br: [],
    dd: ["style"],
    div: ["align", "style"],
    dl: ["style"],
    dt: ["style"],
    em: [],
    figcaption: ["style"],
    figure: ["style"],
    font: ["color", "face", "size", "style"],
    h1: ["style"],
    h2: ["style"],
    h3: ["style"],
    h4: ["style"],
    h5: ["style"],
    h6: ["style"],
    hr: [],
    i: [],
    img: ["alt", "border", "height", "src", "style", "width"],
    li: [],
    ol: [],
    p: ["style"],
    source: ["media", "src", "type"],
    span: ["style"],
    strong: [],
    sub: ["style"],
    sup: ["style"],
    table: ["border", "cellpadding", "cellspacing", "height", "style", "width"],
    tbody: [],
    tr: ["align", "height", "style", "valign"],
    td: [
      "align",
      "colspan",
      "height",
      "nowrap",
      "rowspan",
      "style",
      "valign",
      "width",
    ],
    th: [
      "align",
      "colspan",
      "height",
      "nowrap",
      "rowspan",
      "style",
      "valign",
      "width",
    ],
    u: [],
    ul: [],
    video: [
      "autoplay",
      "controls",
      "height",
      "loop",
      "muted",
      "poster",
      "preload",
      "width",
    ],
  };
  public readonly allowedProtocols: string[] = [
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
    "radarscope",
  ];
  public readonly arcgisFilterOptions: XSS.IFilterXSSOptions = {
    allowCommentTag: true,
    safeAttrValue: (
      tag: string,
      name: string,
      value: string,
      cssFilter: XSS.ICSSFilter
    ): string => {
      // Take over safe attribute filtering for `a` `href`, `img` `src`,
      // and `source` `src` attributes, otherwise pass onto the
      // default `XSS.safeAttrValue` method.
      if (
        (tag === "a" && name === "href") ||
        ((tag === "img" || tag === "source") && name === "src")
      ) {
        return this.sanitizeUrl(value);
      }
      return xss.safeAttrValue(tag, name, value, cssFilter);
    },
  };
  public readonly xssFilterOptions: XSS.IFilterXSSOptions;
  private _xssFilter: xss.FilterXSS;
  private readonly _entityMap = {
    "&": "&#x38;",
    "<": "&#x3C;",
    ">": "&#x3E;",
    '"': "&#x22;",
    "'": "&#x27;",
    "/": "&#x2F;",
  };

  constructor(filterOptions?: XSS.IFilterXSSOptions, extendDefaults?: boolean) {
    let xssFilterOptions: XSS.IFilterXSSOptions;

    if (filterOptions && !extendDefaults) {
      // Override the defaults
      xssFilterOptions = filterOptions;
    } else if (filterOptions && extendDefaults) {
      // Extend the defaults
      xssFilterOptions = Object.create(this.arcgisFilterOptions);
      Object.keys(filterOptions).forEach((key) => {
        if (key === "whiteList") {
          // Extend the whitelist by concatenating arrays
          xssFilterOptions.whiteList = this._extendObjectOfArrays([
            this.arcgisWhiteList,
            filterOptions.whiteList || {},
          ]);
        } else {
          xssFilterOptions[key] = filterOptions[key];
        }
      });
    } else {
      // Only use the defaults
      xssFilterOptions = Object.create(this.arcgisFilterOptions);
      xssFilterOptions.whiteList = this.arcgisWhiteList;
    }

    this.xssFilterOptions = xssFilterOptions;
    // Make this readable to tests
    this._xssFilter = new xss.FilterXSS(xssFilterOptions);
  }

  /**
   * Sanitizes value to remove invalid HTML tags.
   *
   * Note: If the value passed does not contain a valid JSON data type (String,
   * Number, JSON Object, Array, Boolean, or null), the value will be nullified.
   *
   * @param {any} value The value to sanitize.
   * @returns {any} The sanitized value.
   * @memberof Sanitizer
   */
  public sanitize(value: any, options: ISanitizeOptions = {}): any {
    switch (typeof value) {
      case "number":
        if (isNaN(value) || !isFinite(value)) {
          return null;
        }
        return value;
      case "boolean":
        return value;
      case "string":
        return this._xssFilter.process(value);
      case "object":
        return this._iterateOverObject(value, options);
      default:
        if (options.allowUndefined && typeof value === "undefined") {
          return;
        }
        return null;
    }
  }

  /**
   * Sanitizes a URL string following the allowed protocols and sanitization rules.
   *
   * @param {string} value The URL to sanitize.
   * @param {{ isProtocolRequired: boolean }} options Configuration options for URL checking.
   * @returns {string} The sanitized URL if it's valid, or an empty string if the URL is invalid.
   */
  public sanitizeUrl(value: string, options?: {
    /** Whether a protocol must exist on the URL for it to be considered valid. Defaults to `true`. If `false` and the provided URL has no protocol, it will be automatically prefixed with `https://`. */
    isProtocolRequired?: boolean;
  }): string {
    const { isProtocolRequired = true } = options ?? {};
    const protocol = this._trim(value.substring(0, value.indexOf(":")));
    const isRootUrl = value === '/';
    const isUrlFragment = /^#/.test(value);
    const isValidProtocol = protocol && this.allowedProtocols.indexOf(protocol.toLowerCase()) > -1;

    if (isRootUrl || isUrlFragment || isValidProtocol) {
      return xss.escapeAttrValue(value);
    }
    if (!protocol && !isProtocolRequired) {
      return xss.escapeAttrValue(`https://${value}`);
    }
    return "";
  }

  /**
   * Sanitizes an HTML attribute value.
   *
   * @param {string} tag The tagname of the HTML element.
   * @param {string} attribute The attribute name of the HTML element.
   * @param {string} value The raw value to be used for the HTML attribute value.
   * @param {XSS.ICSSFilter} [cssFilter] The CSS filter to be used.
   * @returns {string} The sanitized attribute value.
   * @memberof Sanitizer
   */
  public sanitizeHTMLAttribute(
    tag: string,
    attribute: string,
    value: string,
    cssFilter?: XSS.ICSSFilter
  ): string {
    // use the custom safeAttrValue function if provided
    if (typeof this.xssFilterOptions.safeAttrValue === "function") {
      return this.xssFilterOptions.safeAttrValue(
        tag,
        attribute,
        value,
        // @ts-expect-error safeAttrValue does handle undefined cssFilter
        cssFilter
      );
    }

    // otherwise use the default
    // @ts-ignore safeAttrValue does handle undefined cssFilter
    return xss.safeAttrValue(tag, attribute, value, cssFilter);
  }

  /**
   * Checks if a value only contains valid HTML.
   *
   * @param {any} value The value to validate.
   * @returns {boolean}
   * @memberof Sanitizer
   */
  public validate(
    value: any,
    options: ISanitizeOptions = {}
  ): IValidationResponse {
    const sanitized = this.sanitize(value, options);

    return {
      isValid: value === sanitized,
      sanitized,
    };
  }

  /**
   * Encodes the following characters, `& < > \" ' /` to their hexadecimal HTML entity code.
   * Example: "&middot;" => "&#x38;middot;"
   *
   * @param {string} value The value to encode.
   * @returns {string} The encoded string value.
   * @memberof Sanitizer
   */
  public encodeHTML(value: string): string {
    return String(value).replace(/[&<>"'\/]/g, (s) => {
      return this._entityMap[s];
    });
  }

  /**
   * Encodes all non-alphanumeric ASCII characters to their hexadecimal HTML entity codes.
   * Example: "alert(document.cookie)" => "alert&#x28;document&#x2e;cookie&#x29;"
   *
   * @param {string} value The value to encode.
   * @returns {string} The encoded string value.
   * @memberof Sanitizer
   */
  public encodeAttrValue(value: string): string {
    const alphanumericRE = /^[a-zA-Z0-9]$/;
    return String(value).replace(/[\x00-\xFF]/g, (c, idx) => {
      return !alphanumericRE.test(c)
        ? `&#x${Number(value.charCodeAt(idx)).toString(16)};`
        : c;
    });
  }

  /**
   * Extends an object of arrays by by concatenating arrays of the same object
   * keys. If the if the previous key's value is not an array, the next key's
   * value will replace the previous key. This method is used for extending the
   * whiteList in the XSS filter options.
   *
   * @private
   * @param {Array<{}>} objects An array of objects.
   * @returns {{}} The extended object.
   * @memberof Sanitizer
   */
  private _extendObjectOfArrays(objects: {}[]): {} {
    const finalObj = {};

    objects.forEach((obj) => {
      Object.keys(obj).forEach((key) => {
        if (Array.isArray(obj[key]) && Array.isArray(finalObj[key])) {
          finalObj[key] = finalObj[key].concat(obj[key]);
        } else {
          finalObj[key] = obj[key];
        }
      });
    });

    return finalObj;
  }

  /**
   * Iterate over a plain object or array to deeply sanitize each value.
   *
   * @private
   * @param {object} obj The object to iterate over.
   * @returns {(object | null)} The sanitized object.
   * @memberof Sanitizer
   */
  private _iterateOverObject(
    obj: object,
    options: ISanitizeOptions = {}
  ): object | null | void {
    try {
      let hasChanged = false;
      let changedObj;
      if (Array.isArray(obj)) {
        changedObj = obj.reduce((prev, value) => {
          const validation = this.validate(value, options);
          if (validation.isValid) {
            return prev.concat([value]);
          } else {
            hasChanged = true;
            return prev.concat([validation.sanitized]);
          }
        }, []);
      } else if (!isPlainObject(obj)) {
        if (options.allowUndefined && typeof obj === "undefined") {
          return;
        }
        return null;
      } else {
        const keys = Object.keys(obj);
        changedObj = keys.reduce((prev, key) => {
          const value = obj[key];
          const validation = this.validate(value, options);
          if (validation.isValid) {
            prev[key] = value;
          } else {
            hasChanged = true;
            prev[key] = validation.sanitized;
          }
          return prev;
        }, {});
      }

      if (hasChanged) {
        return changedObj;
      }
      return obj;
    } catch (err) {
      return null;
    }
  }

  /**
   * Trim whitespace from the start and ends of a string.
   * @param {string} val The string to trim.
   * @returns {string} The trimmed string.
   */
  private _trim(val: string): string {
    // @ts-ignore This is used by Jest,
    // but TypeScript errors since it assumes `trim` is always available.
    return String.prototype.trim
      ? val.trim()
      : val.replace(/(^\s*)|(\s*$)/g, "");
  }
}

export default Sanitizer;
