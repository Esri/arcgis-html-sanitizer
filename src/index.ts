/* Copyright (c) 2018 Environmental Systems Research Institute, Inc.
 * Apache-2.0
 *
 * js-xss
 * Copyright (c) 2012-2017 Zongmin Lei(雷宗民) <leizongmin@gmail.com>
 * http://ucdok.com
 * The MIT License, see
 * https://github.com/leizongmin/js-xss/blob/master/LICENSE for details
 * */
import xss from 'xss';

/**
 * The Sanitizer Class
 *
 * @export
 * @class Sanitizer
 */
export class Sanitizer {
  // Supported HTML Spec: https://doc.arcgis.com/en/arcgis-online/reference/supported-html.htm
  public readonly arcgisWhiteList: XSS.IWhiteList = {
    a: ['href', 'target', 'style'],
    img: ['src', 'width', 'height', 'border', 'alt', 'style'],
    video: [
      'autoplay',
      'controls',
      'height',
      'loop',
      'muted',
      'poster',
      'preload',
      'src',
      'width'
    ],
    audio: ['autoplay', 'controls', 'loop', 'muted', 'preload', 'src'],
    span: ['style'],
    table: ['width', 'height', 'cellpadding', 'cellspacing', 'border', 'style'],
    div: ['style', 'class'],
    font: ['size', 'color', 'style'],
    tr: ['height', 'valign', 'align', 'style'],
    td: [
      'height',
      'width',
      'valign',
      'align',
      'colspan',
      'rowspan',
      'nowrap',
      'style'
    ],
    th: [
      'height',
      'width',
      'valign',
      'align',
      'colspan',
      'rowspan',
      'nowrap',
      'style'
    ],
    b: [],
    strong: [],
    i: [],
    em: [],
    br: [],
    p: [],
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
        if (key === 'whiteList') {
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
   * Sanitizes a string to remove invalid HTML tags.
   *
   * @param {string} htmlString The string to sanitize.
   * @returns {string} A string with the invalid HTML removed.
   * @memberof Sanitizer
   */
  public sanitize(htmlString: string): string {
    return this._xssFilter.process(htmlString);
  }

  /**
   * Checks if a string only contains valid HTML.
   *
   * @param {string} htmlString The string to validate.
   * @returns {boolean}
   * @memberof Sanitizer
   */
  public isValidHtml(htmlString: string): boolean {
    return htmlString === this.sanitize(htmlString);
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
}
