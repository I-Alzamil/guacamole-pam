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
            var guacNotification = $injector.get('guacNotification');
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

            var loadConnections = function loadConnections() {
                return pamService.getConnections().then(function connectionsRetrieved(connections) {
                    $scope.connections = connections;
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
                pamService.getConnections().then(function connectionsRetrieved(connections) {
                    $scope.connections = connections;
                });
            }, REFRESH_INTERVAL);

            $scope.$on('$destroy', function settingsPamRotationDestroyed() {
                $interval.cancel(refresh);
            });

        }]
    };

}]);
