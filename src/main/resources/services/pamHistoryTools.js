/**
 * Searching and exporting shared by the checkout and approvals histories,
 * which work like Guacamole's own connection history.
 */
angular.module('guacPam').factory('pamHistoryTools', ['$injector', function pamHistoryTools($injector) {

    // Required types
    var FilterToken = $injector.get('FilterToken');

    // Required services
    var csvService = $injector.get('csvService');

    /**
     * First characters which make a spreadsheet read a cell as a formula.
     */
    var FORMULA_START = /^[=+\-@\t\r]/;

    var service = {};

    /**
     * Splits a search string into terms, every one of which must match.
     * Quoted phrases stay whole, as in Guacamole's history.
     */
    service.getTerms = function getTerms(searchString) {
        var terms = [];
        angular.forEach(FilterToken.tokenize(searchString || ''), function addTerm(token) {
            if (token.type === 'LITERAL')
                terms.push(token.value);
            else if (token.type !== 'WHITESPACE')
                terms.push(token.consumed);
        });
        return terms;
    };

    /**
     * A cell value as written to CSV. Text anyone may enter (reasons, names)
     * is kept from being run as a spreadsheet formula when the file is
     * opened, by prefixing it with an apostrophe as spreadsheets do.
     */
    var toCell = function toCell(value) {
        if (typeof value === 'string' && FORMULA_START.test(value))
            return '\'' + value;
        return value;
    };

    /**
     * Saves the given rows (the first one being the headers) as a CSV file.
     */
    service.saveCsv = function saveCsv(records, filename) {
        saveAs(csvService.toBlob(records.map(function toRow(record) {
            return record.map(toCell);
        })), filename);
    };

    return service;

}]);
