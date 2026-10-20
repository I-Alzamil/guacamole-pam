/**
 * Dialog for requesting an Account's password or access to a connection,
 * showing the password while checked out (of a connection, only if it
 * allows it, and when asked), and releasing it. The password is only kept
 * while the dialog shows it, and is never written to storage.
 */
angular.module('guacPam').directive('pamRequestDialog', [function pamRequestDialog() {

    return {
        restrict    : 'E',
        replace     : true,
        scope       : {},
        templateUrl : 'app/ext/pam/templates/pamRequestDialog.html',
        controller  : ['$scope', '$injector', function pamRequestDialogController($scope, $injector) {

            // Required services
            var $document         = $injector.get('$document');
            var $interval         = $injector.get('$interval');
            var pamPasswordCopy   = $injector.get('pamPasswordCopy');
            var pamRequestService = $injector.get('pamRequestService');
            var pamService        = $injector.get('pamService');

            /**
             * Delay before "Copied" disappears, in milliseconds.
             */
            var COPIED_DURATION = 2000;

            /**
             * Identifier of the connection shown, or null when closed.
             */
            $scope.identifier = null;

            /**
             * The request as returned by the server (no secrets), or null.
             */
            $scope.request = null;

            /**
             * The checked out password and its details, or null.
             */
            $scope.grant = null;

            $scope.form = { reason : '' };

            $scope.busy = false;
            $scope.error = null;
            $scope.revealed = false;
            $scope.copied = false;
            $scope.expired = false;

            /**
             * Remaining time of the checkout, in seconds.
             */
            $scope.remaining = 0;

            var countdown = null;
            var copiedTimer = null;

            /**
             * How often a request awaiting approval is checked, in
             * milliseconds.
             */
            var PENDING_POLL_INTERVAL = 5000;

            var pendingPoll = null;

            var stopPolling = function stopPolling() {
                $interval.cancel(pendingPoll);
                pendingPoll = null;
            };

            /**
             * Keeps checking a request awaiting approval while the dialog is
             * open, so its approval shows up without reopening.
             */
            var pollWhilePending = function pollWhilePending() {
                if ($scope.request && $scope.request.pending && !pendingPoll)
                    pendingPoll = $interval(function checkPending() {
                        pamService.getRequest($scope.identifier).then(function requestRetrieved(request) {
                            $scope.request = request;
                            if (!request.pending) {
                                stopPolling();
                                pamRequestService.refresh();
                            }
                            if (request.mine) {
                                startCountdown(request.expires);
                                pamRequestService.refresh();
                            }
                        });
                    }, PENDING_POLL_INTERVAL);
                else if ($scope.request && !$scope.request.pending)
                    stopPolling();
            };

            /**
             * Whether the user can request the password now.
             */
            $scope.canRequest = function canRequest() {
                var request = $scope.request;
                return !!request && !request.mine && !request.heldExclusively && !request.pending && !$scope.expired;
            };

            var forgetPassword = function forgetPassword() {
                $scope.grant = null;
                $scope.revealed = false;
                $scope.copied = false;
            };

            var stopCountdown = function stopCountdown() {
                $interval.cancel(countdown);
                countdown = null;
            };

            var startCountdown = function startCountdown(expires) {
                stopCountdown();
                var tick = function tick() {
                    $scope.remaining = Math.max(0, Math.round((expires - Date.now()) / 1000));
                    if ($scope.remaining === 0) {
                        stopCountdown();
                        forgetPassword();
                        $scope.expired = true;
                    }
                };
                tick();
                countdown = $interval(tick, 1000);
            };

            var showError = function showError(error) {
                $scope.error = (error && error.message) || 'Request failed.';
            };

            var load = function load() {
                $scope.busy = true;
                return pamService.getRequest($scope.identifier).then(function requestRetrieved(request) {
                    $scope.request = request;
                    if (request.mine)
                        startCountdown(request.expires);
                    pollWhilePending();
                    return request;
                }, showError)['finally'](function loaded() {
                    $scope.busy = false;
                });
            };

            /**
             * Whether opening the dialog checks out the password right away:
             * an Account allowing access without a request, that the user
             * can check out now (still recorded as a checkout).
             */
            var checksOutOnOpen = function checksOutOnOpen(request) {
                return !!request && request.account && request.noRequest && $scope.canRequest();
            };

            $scope.$on('pamRequestOpen', function open(event, identifier) {
                $scope.close();
                $scope.identifier = identifier;
                load().then(function requestLoaded(request) {
                    if (checksOutOnOpen(request))
                        $scope.requestPassword();
                });
            });

            $scope.close = function close() {
                stopCountdown();
                stopPolling();
                forgetPassword();
                $scope.identifier = null;
                $scope.request = null;
                $scope.form.reason = '';
                $scope.error = null;
                $scope.expired = false;
            };

            /**
             * Checks out the password, or shows it again if already held.
             */
            $scope.requestPassword = function requestPassword() {

                $scope.busy = true;
                $scope.error = null;

                pamService.requestPassword($scope.identifier, $scope.form.reason)
                .then(function requested(result) {

                    $scope.form.reason = '';

                    // Awaiting approval: the result is the request status
                    if (!result.checkoutId) {
                        $scope.request = result;
                        pollWhilePending();
                        pamRequestService.refresh();
                        return;
                    }

                    // Granted: a password for an Account, access otherwise
                    if ($scope.request.account)
                        $scope.grant = result;
                    $scope.request.mine = true;
                    $scope.request.expires = result.expires;
                    startCountdown(result.expires);
                    pamRequestService.refresh();

                }, function requestFailed(error) {
                    showError(error);
                    load();
                })['finally'](function requested() {
                    $scope.busy = false;
                });

            };

            /**
             * Translation key of a text of the dialog: the Account wording
             * (about passwords), or the wording for access to a connection.
             */
            $scope.textKey = function textKey(name) {
                return 'PAM.REQUEST.' + ($scope.request && !$scope.request.account ? 'ACCESS_' : '') + name;
            };

            /**
             * Opens a session on the connection the user holds access to.
             */
            $scope.connect = function connect() {
                var identifier = $scope.identifier;
                $scope.close();
                pamRequestService.connect(identifier);
            };

            $scope.cancelRequest = function cancelRequest() {

                $scope.busy = true;
                $scope.error = null;

                pamService.cancelRequest($scope.identifier).then(function cancelled() {
                    pamRequestService.refresh();
                    return load();
                }, showError)['finally'](function cancelled() {
                    stopPolling();
                    $scope.busy = false;
                });

            };

            $scope.releasePassword = function releasePassword() {

                $scope.busy = true;
                $scope.error = null;

                pamService.releasePassword($scope.identifier).then(function released() {
                    stopCountdown();
                    forgetPassword();
                    pamRequestService.refresh();
                    return load();
                }, showError)['finally'](function releaseDone() {
                    $scope.busy = false;
                });

            };

            /**
             * Shows the password of the connection held, where allowed.
             */
            $scope.showConnectionPassword = function showConnectionPassword() {

                $scope.busy = true;
                $scope.error = null;

                pamService.revealPassword($scope.identifier).then(function revealed(grant) {
                    $scope.grant = grant;
                }, function revealFailed(error) {
                    showError(error);
                    load();
                })['finally'](function revealDone() {
                    $scope.busy = false;
                });

            };

            $scope.toggleReveal = function toggleReveal() {
                $scope.revealed = !$scope.revealed;
            };

            /**
             * Copies the password; if the browser refuses, shows it to be
             * copied by hand.
             */
            $scope.copyPassword = function copyPassword() {

                var password = $scope.grant && $scope.grant.password;
                if (!password)
                    return;

                pamPasswordCopy(password).then(function passwordCopied() {
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

            /**
             * Whether the account URL can be offered as a link. Anything but
             * http(s) is shown as text, so a stored URL cannot run script.
             */
            $scope.isWebLink = function isWebLink(url) {
                return /^https?:\/\//i.test(url || '');
            };

            /**
             * Remaining time as "H:MM:SS" or "M:SS".
             */
            $scope.formatRemaining = function formatRemaining() {
                var seconds = $scope.remaining % 60;
                var minutes = Math.floor($scope.remaining / 60) % 60;
                var hours = Math.floor($scope.remaining / 3600);
                var pad = function pad(n) { return (n < 10 ? '0' : '') + n; };
                return (hours ? hours + ':' + pad(minutes) : minutes) + ':' + pad(seconds);
            };

            var closeOnEscape = function closeOnEscape(e) {
                if (e.key === 'Escape' && $scope.identifier !== null)
                    $scope.$apply($scope.close);
            };

            $document.on('keydown', closeOnEscape);
            $scope.$on('$destroy', function dialogDestroyed() {
                $document.off('keydown', closeOnEscape);
                stopCountdown();
                stopPolling();
                $interval.cancel(copiedTimer);
            });

        }]
    };

}]);
