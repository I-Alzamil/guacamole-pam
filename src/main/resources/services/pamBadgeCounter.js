/**
 * Creates the counter behind a notification badge: a count needing the
 * user's attention, refreshed regularly while started, and zero while
 * stopped.
 */
angular.module('guacPam').factory('pamBadgeCounter', ['$injector', function pamBadgeCounter($injector) {

    var $interval = $injector.get('$interval');

    /**
     * How often a count refreshes, in milliseconds.
     */
    var REFRESH_INTERVAL = 30000;

    /**
     * Returns a counter using the given function, which resolves to the
     * current count.
     */
    return function createCounter(fetchCount) {

        var counter = {};

        var count = 0;

        var timer = null;

        counter.count = function getCount() {
            return count;
        };

        /**
         * Fetches the count now, if started.
         */
        counter.refresh = function refresh() {
            if (!timer)
                return;
            // Applied only if counting was not stopped or started again
            // meanwhile, as for another user
            var counting = timer;
            return fetchCount().then(function counted(value) {
                if (timer === counting)
                    count = value || 0;
            }, function countFailed(error) {
                if (timer !== counting)
                    return;
                // Logged out, or the session ended: started again at login
                if (error && error.type === 'PERMISSION_DENIED')
                    counter.stop();
                count = 0;
            });
        };

        /**
         * Starts counting if the user wants and may have this badge, or
         * stops otherwise.
         */
        counter.start = function start(enabled) {
            counter.stop();
            if (!enabled)
                return;
            timer = $interval(counter.refresh, REFRESH_INTERVAL);
            counter.refresh();
        };

        counter.stop = function stop() {
            $interval.cancel(timer);
            timer = null;
            count = 0;
        };

        return counter;

    };

}]);
