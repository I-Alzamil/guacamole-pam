package org.apache.guacamole.pam.management;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * What testing a platform's settings found, step by step, as returned by
 * the REST API. A test stops at its first failed step.
 */
public class PlatformTestResult {

    public enum Status { PASSED, FAILED, INFO }

    /**
     * One step of a test.
     */
    public static final class Step {

        private final Status status;
        private final String text;

        Step(Status status, String text) {
            this.status = status;
            this.text = text;
        }

        public Status getStatus() {
            return status;
        }

        public String getText() {
            return text;
        }

    }

    private final List<Step> steps = new ArrayList<>();

    public PlatformTestResult passed(String text) {
        steps.add(new Step(Status.PASSED, text));
        return this;
    }

    public PlatformTestResult failed(String text) {
        steps.add(new Step(Status.FAILED, text));
        return this;
    }

    public PlatformTestResult info(String text) {
        steps.add(new Step(Status.INFO, text));
        return this;
    }

    public List<Step> getSteps() {
        return Collections.unmodifiableList(steps);
    }

    /**
     * Whether no step failed.
     */
    public boolean isSuccess() {
        for (Step step : steps) {
            if (step.status == Status.FAILED)
                return false;
        }
        return true;
    }

}
