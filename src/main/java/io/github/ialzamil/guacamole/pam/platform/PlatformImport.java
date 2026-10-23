package io.github.ialzamil.guacamole.pam.platform;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.guacamole.GuacamoleClientException;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;

/**
 * Imports platforms, as exported from the Platforms page, all or nothing:
 * every platform is checked as when saved in the editor, and only if all
 * pass are they saved, in one transaction. Platforms are matched by name.
 *
 * Exports carry no secrets, which never leave the server. An imported
 * platform may give them, among its settings; updating one without them
 * keeps those stored, unless where they are sent changes.
 */
public class PlatformImport {

    /**
     * What an import does with a platform.
     */
    public static final String CREATED = "CREATED";
    public static final String UPDATED = "UPDATED";
    public static final String SKIPPED = "SKIPPED";
    public static final String INVALID = "INVALID";

    /**
     * Most platforms one import takes.
     */
    private static final int MAX_PLATFORMS = 500;

    /**
     * What to do with an imported platform named as one that exists.
     */
    public enum Existing {

        /** Refuse the import. */
        REFUSE,

        /** Update the existing platform. */
        UPDATE,

        /** Leave the existing platform alone. */
        SKIP

    }

    /**
     * An import request: the platforms, and whether those named as
     * existing ones update them.
     */
    public static final class Request {

        private List<Platform> platforms;

        private boolean update;

        public List<Platform> getPlatforms() {
            return platforms;
        }

        public void setPlatforms(List<Platform> platforms) {
            this.platforms = platforms;
        }

        public boolean isUpdate() {
            return update;
        }

        public void setUpdate(boolean update) {
            this.update = update;
        }

    }

    /**
     * What happened, or would have, to one platform.
     */
    public static final class Result {

        private final String name;
        private final String outcome;
        private final String message;

        Result(String name, String outcome, String message) {
            this.name = name;
            this.outcome = outcome;
            this.message = message;
        }

        public String getName() {
            return name;
        }

        /**
         * CREATED, UPDATED, SKIPPED or INVALID.
         */
        public String getOutcome() {
            return outcome;
        }

        /**
         * Why the platform is invalid, or null.
         */
        public String getMessage() {
            return message;
        }

    }

    /**
     * The outcome of an import: whether it was saved, and the result of each
     * platform, in the order given. When not saved, at least one is INVALID,
     * and the others say what would have happened.
     */
    public static final class Report {

        private final boolean imported;
        private final List<Result> results;

        Report(boolean imported, List<Result> results) {
            this.imported = imported;
            this.results = Collections.unmodifiableList(results);
        }

        public boolean isImported() {
            return imported;
        }

        public List<Result> getResults() {
            return results;
        }

    }

    /**
     * A checked platform, to insert, or to update the one with the given
     * identifier.
     */
    private static final class Planned {

        private final Platform clean;
        private final Integer id;

        Planned(Platform clean, Integer id) {
            this.clean = clean;
            this.id = id;
        }

    }

    private final PlatformRepository repository;

    public PlatformImport(PlatformRepository repository) {
        this.repository = repository;
    }

    /**
     * Imports the given platforms, all or none.
     *
     * @throws GuacamoleClientException
     *     If there are no platforms, or too many.
     */
    public Report run(List<Platform> platforms, Existing existing) throws GuacamoleException {

        if (platforms == null || platforms.isEmpty())
            throw new GuacamoleClientException("There is no platform to import.");
        if (platforms.size() > MAX_PLATFORMS)
            throw new GuacamoleClientException("At most " + MAX_PLATFORMS + " platforms can be imported at once.");

        Map<String, Platform> stored = repository.getAllWithSecretsByName();
        Set<String> names = new HashSet<>();
        List<Result> results = new ArrayList<>();
        List<Planned> planned = new ArrayList<>();
        boolean valid = true;

        for (int i = 0; i < platforms.size(); i++) {

            Platform platform = platforms.get(i);
            String name = platform == null || platform.getName() == null ? null : platform.getName().trim();
            String shown = name == null || name.isEmpty() ? "#" + (i + 1) : name;

            if (platform == null) {
                results.add(new Result(shown, INVALID, "This is not a platform."));
                valid = false;
                continue;
            }

            if (name != null && !name.isEmpty() && !names.add(name)) {
                results.add(new Result(shown, INVALID, "Another platform of the file has this name."));
                valid = false;
                continue;
            }

            Platform current = name == null ? null : stored.get(name);
            if (current != null && existing == Existing.SKIP) {
                results.add(new Result(shown, SKIPPED, null));
                continue;
            }
            if (current != null && existing == Existing.REFUSE) {
                results.add(new Result(shown, INVALID, "A platform with this name exists. Choose to update"
                        + " existing platforms to replace it."));
                valid = false;
                continue;
            }

            try {
                if (current != null && !current.getType().equals(platform.getType()))
                    throw new GuacamoleClientException("The existing platform of this name is of another type,"
                            + " which cannot be changed.");
                planned.add(new Planned(PlatformRepository.sanitize(platform, current),
                        current == null ? null : current.getId()));
                results.add(new Result(shown, current == null ? CREATED : UPDATED, null));
            }
            catch (GuacamoleClientException e) {
                results.add(new Result(shown, INVALID, e.getMessage()));
                valid = false;
            }

        }

        if (!valid)
            return new Report(false, results);

        save(planned);
        return new Report(true, results);

    }

    /**
     * Adds back the default platforms ({@link DefaultPlatforms}) missing by
     * name. Those that exist are left as they are, even if changed, as
     * connections may rely on them.
     */
    public Report restoreDefaults() throws GuacamoleException {
        return run(DefaultPlatforms.read(), Existing.SKIP);
    }

    private void save(List<Planned> planned) throws GuacamoleException {

        try (Connection connection = repository.getConnection()) {

            connection.setAutoCommit(false);
            try {
                for (Planned platform : planned) {
                    if (platform.id == null)
                        repository.insert(connection, platform.clean, false);
                    else
                        repository.update(connection, platform.id, platform.clean);
                }
                connection.commit();
            }
            catch (SQLException | GuacamoleException e) {
                connection.rollback();
                throw e;
            }

        }
        catch (SQLException e) {
            if (repository.isUniqueViolation(e))
                throw new GuacamoleClientException("A platform was saved meanwhile under one of these names."
                        + " Import again.");
            throw new GuacamoleServerException("Unable to import the platforms.", e);
        }

    }

}
