/**
 * The "Checkouts" settings tab: checkouts active now, which can be revoked,
 * and below them the searchable history of every checkout.
 */
angular.module('guacPam').directive('guacSettingsPamCheckouts', [function guacSettingsPamCheckouts() {

    return {
        restrict    : 'E',
        replace     : true,
        scope       : {},
        templateUrl : 'app/ext/pam/templates/settingsPamCheckouts.html',
        controller  : ['$scope', '$injector', function settingsPamCheckoutsController($scope, $injector) {

            // Required services
            var $document        = $injector.get('$document');
            var $interval        = $injector.get('$interval');
            var guacNotification = $injector.get('guacNotification');
            var pamService       = $injector.get('pamService');

            /**
             * How often the active checkouts refresh, in milliseconds.
             */
            var REFRESH_INTERVAL = 10000;

            /**
             * Active checkouts, or null while loading.
             */
            $scope.activeCheckouts = null;

            /**
             * The checkout whose reason is shown in full, or null.
             */
            $scope.reasonShown = null;

            /**
             * The checkout whose details are shown, as {checkout, details}
             * ("holder", "approvals", "extensions" or "ended"), or null.
             */
            $scope.detailsShown = null;

            var loadCheckouts = function loadCheckouts() {
                pamService.getActiveCheckouts().then(function activeRetrieved(checkouts) {
                    $scope.activeCheckouts = checkouts;
                });
            };

            $scope.showReason = function showReason(checkout) {
                $scope.reasonShown = checkout;
            };

            // From the history below, which shows reasons in this dialog too
            $scope.$on('pamShowCheckoutReason', function showHistoryReason(event, checkout) {
                $scope.showReason(checkout);
            });

            /**
             * Shows who holds a checkout, who approved it, or who ended it,
             * with where they did so from.
             */
            $scope.showDetails = function showDetails(checkout, details) {
                $scope.detailsShown = { checkout : checkout, details : details };
            };

            $scope.$on('pamShowCheckoutDetails', function showHistoryDetails(event, checkout, details) {
                $scope.showDetails(checkout, details);
            });

            /**
             * Closes the details; when given a click, only one on the
             * backdrop itself.
             */
            $scope.closeDetails = function closeDetails($event) {
                if ($event && $event.target !== $event.currentTarget)
                    return;
                $scope.detailsShown = null;
            };

            /**
             * Closes the reason; when given a click, only one on the
             * backdrop itself.
             */
            $scope.closeReason = function closeReason($event) {
                if ($event && $event.target !== $event.currentTarget)
                    return;
                $scope.reasonShown = null;
            };

            $scope.revokeCheckout = function revokeCheckout(checkout) {

                guacNotification.showStatus({
                    title   : 'PAM.DIALOG_HEADER_REVOKE_CHECKOUT',
                    text    : {
                        key       : 'PAM.TEXT_CONFIRM_REVOKE_CHECKOUT',
                        variables : { USER : checkout.username, NAME : checkout.connectionName }
                    },
                    actions : [{
                        name      : 'PAM.ACTION_REVOKE',
                        className : 'danger',
                        callback  : function confirmRevoke() {
                            guacNotification.showStatus(false);
                            pamService.revokeCheckout(checkout.id)
                            ['catch'](guacNotification.SHOW_REQUEST_ERROR)
                            ['finally'](function revoked() {
                                loadCheckouts();
                                $scope.$broadcast('pamCheckoutsChanged');
                            });
                        }
                    }, {
                        name     : 'PAM.ACTION_CANCEL',
                        callback : function cancelRevoke() {
                            guacNotification.showStatus(false);
                        }
                    }]
                });

            };

            var closeOnEscape = function closeOnEscape(e) {
                if (e.key === 'Escape' && ($scope.reasonShown || $scope.detailsShown))
                    $scope.$apply(function closeDialogs() {
                        $scope.reasonShown = null;
                        $scope.detailsShown = null;
                    });
            };

            $document.on('keydown', closeOnEscape);

            loadCheckouts();

            var refresh = $interval(loadCheckouts, REFRESH_INTERVAL);

            $scope.$on('$destroy', function settingsPamCheckoutsDestroyed() {
                $interval.cancel(refresh);
                $document.off('keydown', closeOnEscape);
            });

        }]
    };

}]);
