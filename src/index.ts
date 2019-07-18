/* Copyright (c) 2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0
 *
 * js-xss
 * Copyright (c) 2012-2017 Zongmin Lei(雷宗民) <leizongmin@gmail.com>
 * http://ucdok.com
 * The MIT License, see
 * https://github.com/leizongmin/js-xss/blob/master/LICENSE for details
 * 
 * Lodash/isPlainObject
 * Copyright (c) JS Foundation and other contributors <https://js.foundation/>
 * MIT License, see https://raw.githubusercontent.com/lodash/lodash/4.17.10-npm/LICENSE for details
 * */
import isPlainObject from "lodash.isplainobject";
import xss from "xss";

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

/**
 * The Sanitizer Class
 *
 * @export
 * @class Sanitizer
 */
export class Sanitizer {
  // Supported HTML Spec: https://doc.arcgis.com/en/arcgis-online/reference/supported-html.htm
  public readonly arcgisWhiteList: XSS.IWhiteList = {
    a: ["href", "target", "style"],
    img: ["src", "width", "height", "border", "alt", "style"],
    video: [
      "autoplay",
      "controls",
      "height",
      "loop",
      "muted",
      "poster",
      "preload",
      "src",
      "width"
    ],
    audio: ["autoplay", "controls", "loop", "muted", "preload", "src"],
    span: ["style"],
    table: ["width", "height", "cellpadding", "cellspacing", "border", "style"],
    div: ["style", "class"],
    font: ["size", "color", "style"],
    tr: ["height", "valign", "align", "style"],
    td: [
      "height",
      "width",
      "valign",
      "align",
      "colspan",
      "rowspan",
      "nowrap",
      "style"
    ],
    th: [
      "height",
      "width",
      "valign",
      "align",
      "colspan",
      "rowspan",
      "nowrap",
      "style"
    ],
    p: ["style"],
    b: [],
    strong: [],
    i: [],
    em: [],
    u: [],
    br: [],
    li: [],
    ul: [],
    tbody: []
  };
  public readonly arcgisFilterOptions: XSS.IFilterXSSOptions = {
    allowCommentTag: true
  };
  public readonly xssFilterOptions: XSS.IFilterXSSOptions;
  private _xssFilter: XSS.ICSSFilter;

  constructor(filterOptions?: XSS.IFilterXSSOptions, extendDefaults?: boolean) {
    let xssFilterOptions: XSS.IFilterXSSOptions;

    if (filterOptions && !extendDefaults) {
      // Override the defaults
      xssFilterOptions = filterOptions;
    } else if (filterOptions && extendDefaults) {
      // Extend the defaults
      xssFilterOptions = Object.create(this.arcgisFilterOptions);
      Object.keys(filterOptions).forEach(key => {
        if (key === "whiteList") {
          // Extend the whitelist by concatenating arrays
          xssFilterOptions.whiteList = this._extendObjectOfArrays([
            this.arcgisWhiteList,
            filterOptions.whiteList || {}
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
  public sanitize(value: any): any {
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
        return this._iterateOverObject(value);
      default:
        return null;
    }
  }

  /**
   * Checks if a value only contains valid HTML.
   *
   * @param {any} value The value to validate.
   * @returns {boolean}
   * @memberof Sanitizer
   */
  public validate(value: any): IValidationResponse {
    const sanitized = this.sanitize(value);

    return {
      isValid: value === sanitized,
      sanitized
    };
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
  private _extendObjectOfArrays(objects: Array<{}>): {} {
    const finalObj = {};

    objects.forEach(obj => {
      Object.keys(obj).forEach(key => {
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
  private _iterateOverObject(obj: object): object | null {
    try {
      let hasChanged = false;
      let changedObj;
      if (Array.isArray(obj)) {
        changedObj = obj.reduce((prev, value) => {
          const validation = this.validate(value);
          if (validation.isValid) {
            return prev.concat([value]);
          } else {
            hasChanged = true;
            return prev.concat([validation.sanitized]);
          }
        }, []);
      } else if (!isPlainObject(obj)) {
        return null;
      } else {
        const keys = Object.keys(obj);
        changedObj = keys.reduce((prev, key) => {
          const value = obj[key];
          const validation = this.validate(value);
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
}
