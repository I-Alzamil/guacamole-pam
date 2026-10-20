/**
 * What Guacamole's guac-filter matches in the extension's lists: each item's
 * text as shown, translated labels included, in a "pamFilterText" property.
 * The property is not enumerable, so it is never sent back to the server
 * nor copied with the item.
 */
angular.module('guacPam').factory('pamFilterText', [function pamFilterText() {

    /**
     * Sets the text of an item from the given parts, skipping empty ones.
     */
    return function setFilterText(item, parts) {
        Object.defineProperty(item, 'pamFilterText', {
            value        : parts.filter(function isPresent(part) { return part; }).join(' '),
            configurable : true
        });
        return item;
    };

}]);
