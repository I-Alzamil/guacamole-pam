/**
 * Times of the extension, which the server sends as milliseconds since
 * 1970 UTC. They are shown in the browser's time zone, named after them
 * ("pamZone"), so a time read on screen or in a screenshot is never taken
 * for another zone's. Exports give the same local time with its offset
 * from UTC ("pamLocalIso"); "pamUtc" gives the time in UTC.
 */

(function definePamTimeFilters() {

    /**
     * Pads a number to two digits, or three.
     */
    var pamPad = function pamPad(number, digits) {
        var text = String(number);
        while (text.length < (digits || 2))
            text = '0' + text;
        return text;
    };

    /**
     * The offset of the browser's time zone from UTC at the given date, as
     * ISO 8601 writes it: "+03:00", or "-05:00".
     */
    var pamOffset = function pamOffset(date) {
        var minutes = -date.getTimezoneOffset();
        var sign = minutes < 0 ? '-' : '+';
        minutes = Math.abs(minutes);
        return sign + pamPad(Math.floor(minutes / 60)) + ':' + pamPad(minutes % 60);
    };

    /**
     * The time as ISO 8601 in the browser's time zone, with its offset from
     * UTC, such as "2026-10-22T16:18:20.372+03:00": the local time, yet the
     * same moment for any reader or tool. An empty string if there is none.
     */
    angular.module('guacPam').filter('pamLocalIso', [function definePamLocalIso() {
        return function pamLocalIso(time) {
            if (time === null || time === undefined || time === '')
                return '';
            var date = new Date(time);
            return date.getFullYear() + '-' + pamPad(date.getMonth() + 1) + '-' + pamPad(date.getDate())
                    + 'T' + pamPad(date.getHours()) + ':' + pamPad(date.getMinutes()) + ':' + pamPad(date.getSeconds())
                    + '.' + pamPad(date.getMilliseconds(), 3) + pamOffset(date);
        };
    }]);

    /**
     * The time as ISO 8601 in UTC, such as "2026-10-22T13:18:20.372Z", or an
     * empty string if there is none.
     */
    angular.module('guacPam').filter('pamUtc', [function definePamUtc() {
        return function pamUtc(time) {
            if (time === null || time === undefined || time === '')
                return '';
            return new Date(time).toISOString();
        };
    }]);

    /**
     * The name of the browser's time zone at the given time, such as "GMT+3" or
     * "CEST" (it may change with daylight saving time), or an empty string if
     * there is no time.
     */
    angular.module('guacPam').filter('pamZone', [function definePamZone() {

        return function pamZone(time) {

            if (time === null || time === undefined || time === '')
                return '';

            var date = new Date(time);
            try {
                var parts = new Intl.DateTimeFormat(undefined, { timeZoneName : 'short' }).formatToParts(date);
                for (var i = 0; i < parts.length; i++) {
                    if (parts[i].type === 'timeZoneName')
                        return parts[i].value;
                }
            }
            catch (e) {
                // Without Intl, or formatToParts
            }

            // The offset, such as "UTC+03:00", where the browser cannot name it
            return 'UTC' + pamOffset(date);

        };

    }]);

})();
