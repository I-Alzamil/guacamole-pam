/**
 * Dialog for requesting an Account's password or access to a connection
 * (now, or, where approval is needed, ahead of time), showing the password
 * while checked out (of a connection, only if it allows it, and when asked),
 * and releasing it. The password is only kept
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
            var $filter           = $injector.get('$filter');
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

            /**
             * The reason, when access is wanted ("now", or "later" from the
             * given start: a Date, picked to the minute in the browser's
             * time zone), and for how many times the time limit. When
             * extending a checkout, "extending" is true and the reason is
             * that of the extension.
             */
            $scope.form = { reason : '', when : 'now', starts : null, periods : 1, extending : false };

            /**
             * How far ahead access can be requested, in days (as the server
             * allows).
             */
            var MAX_DAYS_AHEAD = 30;

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
             * Timer reloading the request when the user's reservation starts,
             * or null.
             */
            var reservationTimer = null;

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
                if (($scope.request && $scope.request.pending || $scope.extensionPending()) && !pendingPoll)
                    pendingPoll = $interval(function checkPending() {
                        pamService.getRequest($scope.identifier).then(whileShowing(function requestRetrieved(request) {
                            var previous = $scope.request;
                            $scope.request = request;
                            if (!request.pending && !$scope.extensionPending()) {
                                stopPolling();
                                reloadWhenReserved();
                                pamRequestService.refresh();
                            }
                            // The list of requests refreshed only once the
                            // checkout changed, such as extended: it polls
                            // on its own otherwise
                            else if (request.mine && (!previous || previous.expires !== request.expires))
                                pamRequestService.refresh();
                            if (request.mine)
                                startCountdown(request.expires);
                        }));
                    }, PENDING_POLL_INTERVAL);
                else if ($scope.request && !$scope.request.pending && !$scope.extensionPending())
                    stopPolling();
            };

            /**
             * Whether the user's reservation (approved access requested ahead
             * of time) has started, so they can check out with it.
             */
            $scope.reservationStarted = function reservationStarted() {
                var reservation = $scope.request && $scope.request.reservation;
                return !!reservation && reservation.starts <= Date.now();
            };

            /**
             * Whether someone else's reservation of the connection lasts now.
             */
            $scope.reservedNow = function reservedNow() {
                var request = $scope.request;
                return !!request && !!request.reservedBy && request.reservedFrom <= Date.now();
            };

            /**
             * Whether the user can make a request, for now or for later.
             */
            var canMakeRequest = function canMakeRequest() {
                var request = $scope.request;
                return !!request && !request.mine && !request.pending && !$scope.expired
                    && !$scope.reservationStarted();
            };

            /**
             * Whether the user can request the password now.
             */
            $scope.canRequestNow = function canRequestNow() {
                return canMakeRequest() && !$scope.request.heldExclusively && !$scope.reservedNow();
            };

            /**
             * Whether the user can request access ahead of time: only where
             * it needs approval.
             */
            $scope.canRequestLater = function canRequestLater() {
                return canMakeRequest() && $scope.request.approvalsRequired > 0;
            };

            $scope.canRequest = function canRequest() {
                return $scope.canRequestNow() || $scope.canRequestLater();
            };

            /**
             * Whether the request being made is for later.
             */
            $scope.isLater = function isLater() {
                return $scope.canRequestLater() && ($scope.form.when === 'later' || !$scope.canRequestNow());
            };

            /**
             * A time as the dialog shows it: date, time to the minute, and
             * the browser's time zone.
             */
            $scope.formatTime = function formatTime(time) {
                return $filter('date')(time, 'mediumDate') + ' ' + $filter('date')(time, 'shortTime')
                    + ' ' + $filter('pamZone')(time);
            };

            /**
             * Bounds of the start, as the date and time input takes them.
             */
            $scope.startBounds = function startBounds() {
                var format = function format(time) {
                    return $filter('date')(time, 'yyyy-MM-ddTHH:mm');
                };
                var now = Date.now();
                return { min : format(now), max : format(now + MAX_DAYS_AHEAD * 24 * 3600 * 1000) };
            };

            /**
             * When access requested for the picked start would end, or null.
             */
            $scope.laterEnds = function laterEnds() {
                var starts = $scope.form.starts;
                return starts && $scope.request ? starts.getTime() + $scope.requestedMinutes() * 60000 : null;
            };

            /**
             * How long the access being requested lasts, in minutes.
             */
            $scope.requestedMinutes = function requestedMinutes() {
                return $scope.request ? $scope.request.durationMinutes * $scope.form.periods : 0;
            };

            /**
             * The durations that can be asked for, as numbers of time limits.
             */
            $scope.periodChoices = function periodChoices() {
                var choices = [];
                for (var periods = 1; $scope.request && periods <= $scope.request.maxPeriods; periods++)
                    choices.push(periods);
                return choices;
            };

            /**
             * A length of time as "45 min", "2 h" or "1 h 30 min".
             */
            $scope.formatMinutes = function formatMinutes(minutes) {
                var hours = Math.floor(minutes / 60);
                var rest = minutes % 60;
                if (!hours)
                    return rest + ' min';
                return hours + ' h' + (rest ? ' ' + rest + ' min' : '');
            };

            /**
             * Whether a request to extend the user's checkout awaits
             * approval.
             */
            $scope.extensionPending = function extensionPending() {
                var request = $scope.request;
                return !!request && request.mine && !!request.extension && request.extension.status === 'PENDING';
            };

            /**
             * Whether the user can extend their checkout now.
             */
            $scope.canExtend = function canExtend() {
                var request = $scope.request;
                return !!request && request.mine && !$scope.expired && request.extensionsLeft > 0
                    && !$scope.extensionPending();
            };

            /**
             * Extends the user's checkout, or asks for it to be extended,
             * once a reason was given where needed.
             */
            $scope.extend = function extend() {

                if (!$scope.form.extending && !$scope.request.noRequest) {
                    $scope.form.extending = true;
                    return;
                }

                $scope.busy = true;
                $scope.error = null;

                pamService.extend($scope.identifier, $scope.form.reason).then(function extended(request) {
                    resetForm();
                    $scope.request = request;
                    if (request.mine)
                        startCountdown(request.expires);
                    pollWhilePending();
                    pamRequestService.refresh();
                }, function extendFailed(error) {
                    showError(error);
                    load();
                })['finally'](function extendDone() {
                    $scope.busy = false;
                });

            };

            /**
             * Cancels the user's request to extend their checkout.
             */
            $scope.cancelExtension = function cancelExtension() {

                $scope.busy = true;
                $scope.error = null;

                pamService.cancelExtension($scope.identifier).then(function cancelled() {
                    stopPolling();
                    return load();
                }, showError)['finally'](function cancelled() {
                    $scope.busy = false;
                });

            };

            /**
             * Resets the form, picking the start of the next hour for later.
             */
            var resetForm = function resetForm() {
                var next = new Date();
                next.setHours(next.getHours() + 1, 0, 0, 0);
                $scope.form.reason = '';
                $scope.form.when = 'now';
                $scope.form.starts = next;
                $scope.form.periods = 1;
                $scope.form.extending = false;
            };

            /**
             * Reloads the request when the user's reservation starts, if
             * within a day.
             */
            var reloadWhenReserved = function reloadWhenReserved() {
                $interval.cancel(reservationTimer);
                reservationTimer = null;
                var reservation = $scope.request && $scope.request.reservation;
                var wait = reservation ? reservation.starts - Date.now() : -1;
                if (wait > 0 && wait < 24 * 3600 * 1000)
                    reservationTimer = $interval(load, wait + 1000, 1);
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

            /**
             * The given callback, applied only while the dialog still shows
             * the connection it was asked for: an answer arriving once the
             * dialog closed, or shows another, is dropped.
             */
            var whileShowing = function whileShowing(callback) {
                var identifier = $scope.identifier;
                return function applyWhileShowing(value) {
                    if ($scope.identifier === identifier && identifier !== null)
                        return callback(value);
                    return value;
                };
            };

            var load = function load() {
                $scope.busy = true;
                return pamService.getRequest($scope.identifier).then(whileShowing(function requestRetrieved(request) {
                    $scope.request = request;
                    if (request.mine)
                        startCountdown(request.expires);
                    if (!$scope.canRequestNow() && $scope.canRequestLater())
                        $scope.form.when = 'later';
                    pollWhilePending();
                    reloadWhenReserved();
                    return request;
                }), whileShowing(showError))['finally'](function loaded() {
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
                load().then(whileShowing(function requestLoaded(request) {
                    if (checksOutOnOpen(request))
                        $scope.requestPassword();
                }));
            });

            // Never left open, with a password, once the user logged out
            $scope.$on('guacLogout', function loggedOut() {
                $scope.close();
            });

            $scope.close = function close() {
                stopCountdown();
                stopPolling();
                $interval.cancel(reservationTimer);
                reservationTimer = null;
                forgetPassword();
                $scope.identifier = null;
                $scope.request = null;
                resetForm();
                $scope.error = null;
                $scope.expired = false;
            };

            /**
             * Checks out the password, or shows it again if already held;
             * during the user's reservation, checks out with it. Where
             * approval is needed, requests it, for now or for later.
             */
            $scope.requestPassword = function requestPassword() {

                $scope.busy = true;
                $scope.error = null;

                var starts = $scope.isLater() && $scope.form.starts ? $scope.form.starts.getTime() : null;
                var periods = $scope.canRequest() ? $scope.form.periods : 1;
                pamService.requestPassword($scope.identifier, $scope.form.reason, starts, periods)
                .then(whileShowing(function requested(result) {

                    resetForm();

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

                }), whileShowing(function requestFailed(error) {
                    showError(error);
                    load();
                }))['finally'](function requested() {
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

            /**
             * Cancels the user's reservation, not used yet.
             */
            $scope.cancelReservation = function cancelReservation() {

                $scope.busy = true;
                $scope.error = null;

                pamService.cancelReservation($scope.identifier).then(function cancelled() {
                    pamRequestService.refresh();
                    return load();
                }, showError)['finally'](function cancelled() {
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

                pamService.revealPassword($scope.identifier).then(whileShowing(function revealed(grant) {
                    $scope.grant = grant;
                }), whileShowing(function revealFailed(error) {
                    showError(error);
                    load();
                }))['finally'](function revealDone() {
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
                $interval.cancel(reservationTimer);
            });

            resetForm();

        }]
    };

}]);
