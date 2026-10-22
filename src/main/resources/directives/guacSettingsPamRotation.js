/**
 * The "Password Rotation" settings tab: the managed connections, their
 * rotation policy and status, and rotating one, or all those listed, now.
 */
angular.module('guacPam').directive('guacSettingsPamRotation', [function guacSettingsPamRotation() {

    return {
        restrict    : 'E',
        replace     : true,
        scope       : {},
        templateUrl : 'app/ext/pam/templates/settingsPamRotation.html',
        controller  : ['$scope', '$injector', function settingsPamRotationController($scope, $injector) {

            // Required services
            var $document        = $injector.get('$document');
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
             * How many rotations Rotate all runs at once. Each request waits
             * for its rotation to end.
             */
            var ROTATE_ALL_CONCURRENCY = 4;

            /**
             * Identifiers of the connections this page is rotating, kept
             * across refreshes of the list.
             */
            var rotating = {};

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
                    if (rotating[connection.identifier]) {
                        connection.rotating = true;
                        connection.status = 'RUNNING';
                    }
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

            var startRotation = function startRotation(connection) {
                rotating[connection.identifier] = true;
                connection.rotating = true;
                connection.status = 'RUNNING';
                return pamService.rotate(connection.identifier)
                ['finally'](function rotationEnded() {
                    delete rotating[connection.identifier];
                });
            };

            $scope.rotate = function rotate(connection) {
                startRotation(connection)
                ['catch'](guacNotification.SHOW_REQUEST_ERROR)
                ['finally'](loadConnections);
            };

            /**
             * The connections listed, as filtered, not being rotated already.
             */
            $scope.rotatableConnections = function rotatableConnections() {
                return $scope.filteredConnections.filter(function notRotating(connection) {
                    return !connection.rotating;
                });
            };

            /**
             * Rotates the given connections, a few at a time. Their results
             * show in the list; only the number of failed requests is
             * reported, once all have ended.
             */
            var rotateAll = function rotateAll(connections) {

                var queue = connections.slice();
                var failed = 0;
                var running = 0;

                var next = function next() {

                    if (!queue.length) {
                        if (!running) {
                            loadConnections();
                            if (failed)
                                guacNotification.showStatus({
                                    title   : 'PAM.DIALOG_HEADER_ROTATE_ALL',
                                    text    : { key : 'PAM.TEXT_ROTATE_ALL_REQUEST_FAILED', variables : { COUNT : failed } },
                                    actions : [{
                                        name     : 'PAM.ACTION_CLOSE',
                                        callback : function closeFailed() {
                                            guacNotification.showStatus(false);
                                        }
                                    }]
                                });
                        }
                        return;
                    }

                    running++;
                    startRotation(queue.shift())
                    ['catch'](function rotationRequestFailed() {
                        failed++;
                    })
                    ['finally'](function rotationRequestEnded() {
                        running--;
                        loadConnections();
                        next();
                    });

                };

                for (var i = 0; i < ROTATE_ALL_CONCURRENCY && queue.length; i++)
                    next();

            };

            /**
             * Rotates every connection listed, as filtered, once confirmed.
             */
            $scope.confirmRotateAll = function confirmRotateAll() {

                var connections = $scope.rotatableConnections();
                if (!connections.length)
                    return;

                var filtered = $scope.filteredConnections.length < $scope.connections.length;
                guacNotification.showStatus({
                    title   : 'PAM.DIALOG_HEADER_ROTATE_ALL',
                    text    : {
                        key       : filtered ? 'PAM.TEXT_CONFIRM_ROTATE_FILTERED' : 'PAM.TEXT_CONFIRM_ROTATE_ALL',
                        variables : { COUNT : connections.length }
                    },
                    actions : [{
                        name     : 'PAM.ACTION_ROTATE_ALL',
                        callback : function confirmRotate() {
                            guacNotification.showStatus(false);
                            rotateAll(connections);
                        }
                    }, {
                        name     : 'PAM.ACTION_CANCEL',
                        callback : function cancelRotate() {
                            guacNotification.showStatus(false);
                        }
                    }]
                });

            };

            /**
             * The connection whose last rotation's outcome is shown in full,
             * as it was when opened, or null.
             */
            $scope.messageShown = null;

            $scope.showMessage = function showMessage(connection) {
                $scope.messageShown = connection;
            };

            /**
             * Closes the outcome; when given a click, only one on the
             * backdrop itself.
             */
            $scope.closeMessage = function closeMessage($event) {
                if ($event && $event.target !== $event.currentTarget)
                    return;
                $scope.messageShown = null;
            };

            var closeOnEscape = function closeOnEscape(e) {
                if (e.key === 'Escape' && $scope.messageShown)
                    $scope.$apply(function closeMessage() {
                        $scope.messageShown = null;
                    });
            };

            $document.on('keydown', closeOnEscape);

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
                $document.off('keydown', closeOnEscape);
            });

        }]
    };

}]);
