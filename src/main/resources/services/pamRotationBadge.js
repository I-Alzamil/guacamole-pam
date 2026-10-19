/**
 * Number of managed connections whose last rotation failed or could not be
 * confirmed, kept current while an administrator is logged in, for the red
 * badges next to the user menu and on the Password Rotation tab.
 */
angular.module('guacPam').factory('pamRotationBadge', ['$injector', function pamRotationBadge($injector) {

    var $interval  = $injector.get('$interval');
    var pamService = $injector.get('pamService');

    /**
     * How often the count refreshes, in milliseconds.
     */
    var REFRESH_INTERVAL = 30000;

    var service = {};

    var failed = 0;

    var timer = null;

    service.count = function count() {
        return failed;
    };

    service.refresh = function refresh() {
        if (!timer)
            return;
        return pamService.countRotationFailures().then(function counted(result) {
            failed = timer ? result.failed || 0 : 0;
        }, function countFailed() {
            failed = 0;
        });
    };

    /**
     * Starts counting for an administrator, or stops for anyone else.
     */
    service.start = function start(administrator) {
        service.stop();
        if (!administrator)
            return;
        timer = $interval(service.refresh, REFRESH_INTERVAL);
        service.refresh();
    };

    service.stop = function stop() {
        $interval.cancel(timer);
        timer = null;
        failed = 0;
    };

    return service;

}]);
