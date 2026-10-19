/**
 * Opens the request dialog, instead of the client, when a connection needing
 * a request is opened from anywhere in the web UI (home screen, recent
 * connections, bookmarks): always for Accounts, and for other connections
 * unless the user holds access. The server refuses sessions without access
 * regardless, so this only decides what the user sees.
 */
angular.module('guacPam').run(['$injector', function pamRequestRouteConfig($injector) {

    // Required types
    var ClientIdentifier = $injector.get('ClientIdentifier');

    // Required services
    var $compile              = $injector.get('$compile');
    var $location             = $injector.get('$location');
    var $rootScope            = $injector.get('$rootScope');
    var authenticationService = $injector.get('authenticationService');
    var pamRequestService     = $injector.get('pamRequestService');

    /**
     * Data source whose connections can need a request.
     */
    var DATA_SOURCE = 'postgresql';

    /**
     * Returns the identifier of the connection a client route opens, or null
     * if the route does not open a connection of the managed data source.
     */
    var getRequestedConnection = function getRequestedConnection(route) {

        if (!route || !route.$$route || route.$$route.originalPath !== '/client/:id' || !route.params.id)
            return null;

        var clientIdentifier;
        try {
            clientIdentifier = ClientIdentifier.fromString(route.params.id);
        }
        catch (e) {
            return null;
        }

        if (clientIdentifier.type !== ClientIdentifier.Types.CONNECTION
                || clientIdentifier.dataSource !== DATA_SOURCE)
            return null;

        return clientIdentifier.id;

    };

    /**
     * Shows the request dialog in place of the client. Opened directly (from
     * a bookmark, or right after login), there is no page to stay on, so the
     * home screen is loaded behind the dialog.
     */
    var showDialog = function showDialog(identifier, current) {
        if (!current || !current.$$route)
            $location.url('/').replace();
        pamRequestService.open(identifier);
    };

    $rootScope.$on('$routeChangeStart', function interceptRequestConnection(event, next, current) {

        var identifier = getRequestedConnection(next);
        if (identifier === null)
            return;

        if (pamRequestService.isLoaded()) {
            if (pamRequestService.mustRequest(identifier)) {
                event.preventDefault();
                showDialog(identifier, current);
            }
            return;
        }

        // Not known yet: hold the navigation until it is
        var url = $location.url();
        event.preventDefault();
        pamRequestService.refresh().then(function requestsLoaded() {
            if (pamRequestService.mustRequest(identifier))
                showDialog(identifier, current);
            else
                $location.url(url);
        });

    });

    var pamBadgePreferences = $injector.get('pamBadgePreferences');

    /**
     * Starts the notification badges the user may have and wants.
     */
    var startBadge = function startBadge() {
        pamBadgePreferences.load();
    };

    // Keep the set of request connections and the badge current
    $rootScope.$on('guacLogin', function loggedIn() {
        pamRequestService.clear();
        pamRequestService.refresh();
        startBadge();
    });

    $rootScope.$on('guacLogout', function loggedOut() {
        pamRequestService.clear();
        pamBadgePreferences.clear();
    });

    $rootScope.$on('$routeChangeSuccess', function routeChanged(event, current) {
        if (current && current.$$route && current.$$route.originalPath === '/')
            pamRequestService.refresh();
    });

    if (authenticationService.getCurrentToken()) {
        pamRequestService.refresh();
        startBadge();
    }

    // The dialog lives outside any view, so it survives navigation
    var dialog = $compile('<pam-request-dialog></pam-request-dialog>')($rootScope.$new(true));
    angular.element(document.body).append(dialog);

}]);
