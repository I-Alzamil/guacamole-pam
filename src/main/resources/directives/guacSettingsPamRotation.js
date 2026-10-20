/**
 * The "Password Rotation" settings tab: the managed connections, their
 * rotation policy and status, and rotating one now.
 */
angular.module('guacPam').directive('guacSettingsPamRotation', [function guacSettingsPamRotation() {

    return {
        restrict    : 'E',
        replace     : true,
        scope       : {},
        templateUrl : 'app/ext/pam/templates/settingsPamRotation.html',
        controller  : ['$scope', '$injector', function settingsPamRotationController($scope, $injector) {

            // Required services
            var $interval        = $injector.get('$interval');
            var $translate       = $injector.get('$translate');
            var guacNotification = $injector.get('guacNotification');
            var pamFilterText    = $injector.get('pamFilterText');
            var pamService       = $injector.get('pamService');
            var pamRotationBadge = $injector.get('pamRotationBadge');

            /**
             * How often the list refreshes, in milliseconds.
             */
            var REFRESH_INTERVAL = 10000;

            /**
             * Managed connections, or null while loading.
             */
            $scope.connections = null;

            /**
             * The connections matching the filter.
             */
            $scope.filteredConnections = [];

            /**
             * What the filter matches: the connection, its protocol, mode,
             * platform and status, as shown.
             */
            $scope.filteredConnectionProperties = ['pamFilterText'];

            var setConnections = function setConnections(connections) {
                angular.forEach(connections, function addFilterText(connection) {
                    pamFilterText(connection, [
                        connection.name,
                        connection.protocol,
                        $translate.instant($scope.modeKey(connection.mode)),
                        connection.platformName,
                        connection.platformType && $translate.instant('PAM.TYPE_' + connection.platformType.toUpperCase()),
                        connection.status && $translate.instant('PAM.STATUS_' + connection.status)
                    ]);
                });
                $scope.connections = connections;
            };

            var loadConnections = function loadConnections() {
                return pamService.getConnections().then(function connectionsRetrieved(connections) {
                    setConnections(connections);
                    pamRotationBadge.refresh();
                }, guacNotification.SHOW_REQUEST_ERROR);
            };

            $scope.rotate = function rotate(connection) {
                connection.rotating = true;
                connection.status = 'RUNNING';
                pamService.rotate(connection.identifier)
                ['catch'](guacNotification.SHOW_REQUEST_ERROR)
                ['finally'](loadConnections);
            };

            /**
             * Translation key of the label of a rotation mode.
             */
            $scope.modeKey = function modeKey(mode) {
                return 'PAM.MODE_' + (mode || 'never').toUpperCase().replace(/[^A-Z0-9]+/g, '_');
            };

            loadConnections();

            // Pick up rotations triggered after use or by the schedule
            var refresh = $interval(function refreshConnections() {
                pamService.getConnections().then(setConnections);
            }, REFRESH_INTERVAL);

            $scope.$on('$destroy', function settingsPamRotationDestroyed() {
                $interval.cancel(refresh);
            });

        }]
    };

}]);
