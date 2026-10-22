/**
 * Knows which connections need a request (Accounts, and connections
 * requiring access requests), so that opening one shows the request dialog
 * instead of starting a remote session, unless the user holds access to it.
 */
angular.module('guacPam').factory('pamRequestService', ['$injector', function pamRequestService($injector) {

    // Required services
    var $location  = $injector.get('$location');
    var $q         = $injector.get('$q');
    var $rootScope = $injector.get('$rootScope');
    var $timeout   = $injector.get('$timeout');
    var pamService = $injector.get('pamService');

    // Required types
    var ClientIdentifier = $injector.get('ClientIdentifier');

    var service = {};

    /**
     * Identifier of the data source whose connections can need a request
     * (the one whose connections are managed), or null until loaded.
     */
    var dataSource = null;

    /**
     * Connections needing a request that the user may request, by
     * identifier, as {account, mine}, or null until loaded.
     */
    var requestable = null;

    /**
     * Promise of the latest refresh, or null if none is running.
     */
    var refreshing = null;

    /**
     * How often requests awaiting approval are checked, in milliseconds, so
     * an approval shows up on the home screen.
     */
    var PENDING_POLL_INTERVAL = 15000;

    /**
     * Longest wait before an automatic refresh, in milliseconds (timers
     * cannot wait more than about 24 days).
     */
    var MAX_REFRESH_DELAY = 3600000;

    /**
     * Timer of the next automatic refresh, or null.
     */
    var nextRefresh = null;

    /**
     * Refreshes again when held access ends, or soon if a request awaits
     * approval, so the home screen labels stay current.
     */
    var scheduleRefresh = function scheduleRefresh() {

        $timeout.cancel(nextRefresh);
        nextRefresh = null;

        var delay = null;
        angular.forEach(requestable, function checkEntry(entry) {
            var wait = null;
            if (entry.mine && entry.expires)
                wait = Math.max(0, entry.expires - Date.now()) + 1000;
            else if (entry.pending)
                wait = PENDING_POLL_INTERVAL;
            else if (entry.reservation)
                wait = Math.max(0, (entry.reservation.starts > Date.now() ? entry.reservation.starts
                        : entry.reservation.ends) - Date.now()) + 1000;
            if (wait !== null)
                wait = Math.min(wait, MAX_REFRESH_DELAY);
            if (wait !== null && (delay === null || wait < delay))
                delay = wait;
        });

        if (delay !== null)
            nextRefresh = $timeout(service.refresh, delay);

    };

    /**
     * Reloads the set of request connections. Resolves once loaded, even if
     * loading fails (the server refuses sessions for them anyway).
     */
    service.refresh = function refresh() {

        if (refreshing)
            return refreshing;

        var loadDataSource = dataSource !== null ? $q.resolve({ identifier : dataSource })
                : pamService.getDataSource();

        refreshing = $q.all([loadDataSource, pamService.getRequests()]).then(function requestsRetrieved(results) {
            dataSource = results[0].identifier;
            var requests = results[1];
            var identifiers = {};
            angular.forEach(requests, function addRequest(request) {
                identifiers[request.identifier] = {
                    account : request.account,
                    managed : request.managed,
                    mine    : request.mine,
                    bypass  : request.bypass,
                    expires : request.mine ? request.expires : null,
                    pending : !!request.pending,
                    reservation : request.reservation && !request.mine
                            ? { starts : request.reservation.starts, ends : request.reservation.ends } : null,
                    holders : (request.holders ? request.holders.length : 0) + (request.mine ? 1 : 0),
                    passwordShown : !!request.passwordShown
                };
            });
            requestable = identifiers;
            scheduleRefresh();
        }, function requestsFailed() {
            requestable = requestable || {};
        })['finally'](function refreshDone() {
            refreshing = null;
        });

        return refreshing;

    };

    /**
     * Identifier of the data source whose connections can need a request,
     * or null until loaded.
     */
    service.getDataSource = function getDataSource() {
        return dataSource;
    };

    /**
     * Whether the set of request connections has been loaded.
     */
    service.isLoaded = function isLoaded() {
        return requestable !== null;
    };

    /**
     * Whether opening the connection with the given identifier must show the
     * request dialog: it needs a request, and is an Account (whose password
     * is shown there), or is neither held by the user nor bypassed by them as
     * an administrator. Only meaningful once loaded.
     */
    service.mustRequest = function mustRequest(identifier) {
        var entry = requestable && requestable[identifier];
        return !!entry && (entry.account || (!entry.mine && !entry.bypass));
    };

    /**
     * What is known of a connection needing a request ({account, mine,
     * bypass, expires, pending, reservation, holders}), or null.
     */
    service.getEntry = function getEntry(identifier) {
        return (requestable && requestable[identifier]) || null;
    };

    /**
     * Number of users currently holding the password of the given Account,
     * or 0 for anything else.
     */
    service.getAccountHolders = function getAccountHolders(identifier) {
        var entry = requestable && requestable[identifier];
        return entry && entry.account ? entry.holders : 0;
    };

    /**
     * Opens a session on a connection the user holds access to.
     */
    service.connect = function connect(identifier) {
        if (requestable && requestable[identifier])
            requestable[identifier].mine = true;
        $location.url('/client/' + ClientIdentifier.toString({
            dataSource : dataSource,
            type       : ClientIdentifier.Types.CONNECTION,
            id         : identifier
        }));
    };

    /**
     * Opens the request dialog for the given connection.
     */
    service.open = function open(identifier) {
        $rootScope.$broadcast('pamRequestOpen', identifier);
    };

    service.clear = function clear() {
        $timeout.cancel(nextRefresh);
        nextRefresh = null;
        requestable = null;
        dataSource = null;
    };

    /**
     * Returns a promise resolved once loaded.
     */
    service.whenLoaded = function whenLoaded() {
        return requestable !== null ? $q.resolve() : service.refresh();
    };

    return service;

}]);
