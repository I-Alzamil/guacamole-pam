/**
 * Opens the request dialog, instead of the client, when a connection needing
 * a request is opened from anywhere in the web UI (home screen, recent
 * connections, bookmarks, the connections of the menu within a session,
 * also when added beside the current session): always for Accounts, and for
 * other connections unless the user holds access. The server refuses
 * sessions without access regardless, so this only decides what the user
 * sees.
 */
angular.module('guacPam').run(['$injector', function pamRequestRouteConfig($injector) {

    // Required types
    var ClientIdentifier   = $injector.get('ClientIdentifier');
    var ManagedClientGroup = $injector.get('ManagedClientGroup');

    // Required services
    var $compile              = $injector.get('$compile');
    var $location             = $injector.get('$location');
    var $route                = $injector.get('$route');
    var $rootScope            = $injector.get('$rootScope');
    var authenticationService = $injector.get('authenticationService');
    var pamRequestService     = $injector.get('pamRequestService');

    /**
     * Data source whose connections can need a request.
     */
    var DATA_SOURCE = 'postgresql';

    /**
     * Returns the connections of the managed data source a client route
     * opens, as { client: client identifier, id: connection identifier }.
     * A route may open several clients side by side, such as when one is
     * added beside the current session from the menu.
     */
    var getRequestedConnections = function getRequestedConnections(route) {
        if (!isClientRoute(route) || !route.params.id)
            return [];
        return getConnectionsOfClients(route.params.id);
    };

    var isClientRoute = function isClientRoute(route) {
        return !!route && !!route.$$route && route.$$route.originalPath === '/client/:id';
    };

    /**
     * The connections of the managed data source among the clients of a
     * client route's identifier (several joined by ".").
     */
    var getConnectionsOfClients = function getConnectionsOfClients(clients) {

        var connections = [];
        angular.forEach(ManagedClientGroup.getClientIdentifiers(clients), function addClient(client) {

            var clientIdentifier;
            try {
                clientIdentifier = ClientIdentifier.fromString(client);
            }
            catch (e) {
                return;
            }

            if (clientIdentifier.type === ClientIdentifier.Types.CONNECTION
                    && clientIdentifier.dataSource === DATA_SOURCE)
                connections.push({ client : client, id : clientIdentifier.id });

        });

        return connections;

    };

    /**
     * Returns the first of the given connections the user must request, or
     * null.
     */
    var findMustRequest = function findMustRequest(connections) {
        for (var i = 0; i < connections.length; i++) {
            if (pamRequestService.mustRequest(connections[i].id))
                return connections[i];
        }
        return null;
    };

    /**
     * Unticks a connection added beside the current session in the menu,
     * as it was not added.
     */
    var untick = function untick(current, connection) {
        var context = current && current.scope && current.scope.connectionListContext;
        if (context && context.attachedClients)
            delete context.attachedClients[connection.client];
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

    /**
     * Within a session, the client page stays open when the clients it
     * shows change (another connection opened, or added beside it, from the
     * menu): the route is only updated, so the change of URL is intercepted
     * instead. Connections already shown are left alone.
     */
    $rootScope.$on('$locationChangeStart', function interceptClientUpdate(event, newUrl, oldUrl) {

        var current = $route.current;
        if (!isClientRoute(current) || !pamRequestService.isLoaded())
            return;

        var match = /#\/client\/([^?\/]+)/.exec(newUrl || '');
        if (!match)
            return;

        var shown = {};
        angular.forEach(getRequestedConnections(current), function addShown(connection) {
            shown[connection.client] = true;
        });

        var added = getConnectionsOfClients(decodeURIComponent(match[1])).filter(function isAdded(connection) {
            return !shown[connection.client];
        });

        var mustRequest = findMustRequest(added);
        if (mustRequest) {
            event.preventDefault();
            untick(current, mustRequest);
            showDialog(mustRequest.id, current);
        }

    });

    $rootScope.$on('$routeChangeStart', function interceptRequestConnection(event, next, current) {

        var connections = getRequestedConnections(next);
        if (!connections.length)
            return;

        // Stays on the current page (such as the session the connection was
        // to be added beside), showing the dialog over it
        var refuse = function refuse(connection) {
            untick(current, connection);
            showDialog(connection.id, current);
        };

        if (pamRequestService.isLoaded()) {
            var mustRequest = findMustRequest(connections);
            if (mustRequest) {
                event.preventDefault();
                refuse(mustRequest);
            }
            return;
        }

        // Not known yet: hold the navigation until it is
        var url = $location.url();
        event.preventDefault();
        pamRequestService.refresh().then(function requestsLoaded() {
            var mustRequest = findMustRequest(connections);
            if (mustRequest)
                refuse(mustRequest);
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
