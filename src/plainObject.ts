"use strict";

/**
 * Determine if the value is a plain object.
 * @param {*} value The value to check.
 * @returns {boolean} Returns `true` if `value` is a plain object, else `false`.
 */
const isPlainObject = (value: any) => {
  if (typeof value !== "object" || value === null) {
    return false;
  }

  if (Object.prototype.toString.call(value) !== "[object Object]") {
    return false;
  }

  let proto = Object.getPrototypeOf(value);

  if (proto === null) {
    return true;
  }

  while (Object.getPrototypeOf(proto) !== null) {
    proto = Object.getPrototypeOf(proto);
  }

  return Object.getPrototypeOf(value) === proto;
};

export default isPlainObject;
