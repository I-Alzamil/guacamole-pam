/**
 * Section of the menu within a session showing the password of the
 * connection in focus, when the connection allows its holder to see it and
 * the user holds access to it, as in the request dialog. Placed after the
 * clipboard by templates/pamSessionPasswordPatch.html. The password is only
 * kept while the menu is open and the same connection is in focus.
 */
angular.module('guacPam').directive('pamSessionPassword', [function pamSessionPassword() {

    return {
        restrict    : 'E',
        scope       : {
            client : '<'
        },
        templateUrl : 'app/ext/pam/templates/pamSessionPassword.html',
        controller  : ['$scope', '$injector', function pamSessionPasswordController($scope, $injector) {

            // Required types
            var ClientIdentifier = $injector.get('ClientIdentifier');

            // Required services
            var $interval         = $injector.get('$interval');
            var pamPasswordCopy   = $injector.get('pamPasswordCopy');
            var pamRequestService = $injector.get('pamRequestService');
            var pamService        = $injector.get('pamService');

            /**
             * Delay before "Copied" disappears, in milliseconds.
             */
            var COPIED_DURATION = 2000;

            var copiedTimer = null;

            $scope.grant = null;
            $scope.busy = false;
            $scope.error = null;
            $scope.revealed = false;
            $scope.copied = false;

            /**
             * Identifier of the connection in focus, if it is one of the
             * managed data source, or null.
             */
            var connectionId = function connectionId() {
                if (!$scope.client || !$scope.client.id)
                    return null;
                try {
                    var identifier = ClientIdentifier.fromString($scope.client.id);
                    return identifier.type === ClientIdentifier.Types.CONNECTION
                        && identifier.dataSource === pamRequestService.getDataSource() ? identifier.id : null;
                }
                catch (e) {
                    return null;
                }
            };

            $scope.entry = function entry() {
                var id = connectionId();
                return id === null ? null : pamRequestService.getEntry(id);
            };

            $scope.isShown = function isShown() {
                var entry = $scope.entry();
                return !!entry && !entry.account && entry.passwordShown && entry.mine
                    && (!entry.expires || entry.expires > Date.now());
            };

            var forget = function forget() {
                $scope.grant = null;
                $scope.revealed = false;
                $scope.copied = false;
                $scope.error = null;
            };

            // Another connection in focus, or access ended
            $scope.$watch(function focused() {
                return connectionId() + ':' + $scope.isShown();
            }, forget);

            $scope.show = function show() {

                var id = connectionId();
                if (id === null)
                    return;

                $scope.busy = true;
                $scope.error = null;

                pamService.revealPassword(id).then(function revealed(grant) {
                    if (connectionId() === id)
                        $scope.grant = grant;
                }, function revealFailed(error) {
                    $scope.error = (error && error.message) || 'Request failed.';
                    pamRequestService.refresh();
                })['finally'](function revealDone() {
                    $scope.busy = false;
                });

            };

            $scope.toggleReveal = function toggleReveal() {
                $scope.revealed = !$scope.revealed;
            };

            $scope.copy = function copy() {
                if (!$scope.grant || !$scope.grant.password)
                    return;
                pamPasswordCopy($scope.grant.password).then(function passwordCopied() {
                    $scope.copied = true;
                    $interval.cancel(copiedTimer);
                    copiedTimer = $interval(function hideCopied() {
                        $scope.copied = false;
                    }, COPIED_DURATION, 1);
                }, function copyFailed() {
                    $scope.error = 'Unable to copy. Select the password and copy it manually.';
                    $scope.revealed = true;
                });
            };

            $scope.$on('$destroy', function sectionDestroyed() {
                $interval.cancel(copiedTimer);
                forget();
            });

        }]
    };

}]);
