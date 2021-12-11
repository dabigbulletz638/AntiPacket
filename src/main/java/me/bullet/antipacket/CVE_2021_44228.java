package me.bullet.antipacket;

import me.bullet.antipacket.util.Reflection;
import org.apache.logging.log4j.core.net.JndiManager;

import javax.naming.*;
import javax.naming.directory.*;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.*;

public final class CVE_2021_44228 {
    public static void patch() {
        patchAndHookJndiManager();
    }

    private static void patchAndHookJndiManager() {
        final JndiManager defaultManager = JndiManager.getDefaultManager();

        final Set<ClassLoader> classLoaders = new HashSet<>();
        classLoaders.add(CVE_2021_44228.class.getClassLoader());
        classLoaders.add(JndiManager.class.getClassLoader());
        classLoaders.add(Thread.currentThread().getContextClassLoader());
        classLoaders.add(ClassLoader.getSystemClassLoader());
        boolean fixed = false;
        final List<Throwable> causes = new ArrayList<>();
        try {
            if (patchJndiContext(defaultManager)) {
                fixed = true;
            }
        } catch (final Throwable t) {
            causes.add(t);
        }
        for (final ClassLoader classLoader : classLoaders) {
            if (classLoader == null) {
                continue;
            }
            try {
                Class<?> clazz;
                try {
                    clazz = classLoader.loadClass("org.apache.logging.log4j.core.appender.AbstractManager");
                } catch (final Throwable t) {
                    clazz = Class.forName("org.apache.logging.log4j.core.appender.AbstractManager", false, classLoader);
                }
                if (clazz != null) {
                    final Field[] fields = clazz.getDeclaredFields();
                    for (final Field field : fields) {
                        if (Modifier.isStatic(field.getModifiers()) && Map.class.isAssignableFrom(field.getType())) {
                            Reflection.stripFinal(field).setAccessible(true);
                            final Map<?, ?> map = (Map<?, ?>) field.get(null);
                            // noinspection all
                            final Map<?, ?> hookedMap = new HashMap(map != null ? map : Collections.emptyMap()) {
                                @Override
                                public void putAll(final Map m) {
                                    if (m != null && !m.isEmpty()) {
                                        for (final Object value : m.values()) {
                                            this.putHook(value);
                                        }
                                    }
                                    // noinspection all
                                    super.putAll(m);
                                }

                                @Override
                                public Object putIfAbsent(final Object key, final Object value) {
                                    this.putHook(value);
                                    // noinspection all
                                    return super.putIfAbsent(key, value);
                                }

                                @Override
                                public Object put(final Object key, final Object value) {
                                    this.putHook(value);
                                    // noinspection all
                                    return super.put(key, value);
                                }

                                private void putHook(final Object value) {
                                    if (value instanceof JndiManager) {
                                        try {
                                            if (!patchJndiContext((JndiManager) value)) {
                                                throw verifyError();
                                            }
                                        } catch (final Throwable t) {
                                            final VerifyError error = verifyError();
                                            error.addSuppressed(t);
                                            throw error;
                                        }
                                    }
                                }
                            };
                            field.set(null, hookedMap);
                            if (map == null) {
                                continue;
                            }
                            for (final Object value : map.values()) {
                                if (value instanceof JndiManager) {
                                    try {
                                        if (patchJndiContext((JndiManager) value)) {
                                            fixed = true;
                                        }
                                    } catch (final Throwable t) {
                                        causes.add(t);
                                    }
                                }
                            }
                            map.clear();
                        }
                    }
                }
            } catch (final Throwable t) {
                t.printStackTrace();
            }
        }
        if (!fixed) {
            final VerifyError error = verifyError();
            for (final Throwable cause : causes) {
                error.addSuppressed(cause);
            }
            throw error;
        }
    }

    private static VerifyError verifyError() {
        return new VerifyError("Failed to patch JNDI context to fix CVE-2021-44228");
    }

    private static boolean patchJndiContext(final JndiManager jndiManager) throws ReflectiveOperationException {
        boolean fixed = false;
        Class<?> currClass = jndiManager.getClass();
        while (currClass != null) {
            final Field[] fields = currClass.getDeclaredFields();
            for (final Field field : fields) {
                if (Context.class.isAssignableFrom(field.getType())) {
                    Reflection.stripFinal(field).setAccessible(true);
                    field.set(jndiManager, NoopContext.NOOP_CONTEXT);
                    fixed = true;
                }
            }
            currClass = currClass.getSuperclass();
        }
        return fixed;
    }

    public static final class NoopContext implements Context, DirContext {
        public static final NoopContext NOOP_CONTEXT = new NoopContext();

        @Override
        public Object lookup(final Name name) {
            return null;
        }

        @Override
        public Object lookup(final String name) {
            return null;
        }

        @Override
        public Attributes getAttributes(final Name name) throws NamingException {
            throw noop();
        }

        @Override
        public Attributes getAttributes(final String name) throws NamingException {
            throw noop();
        }

        @Override
        public Attributes getAttributes(final Name name, final String[] attrIds) throws NamingException {
            throw noop();
        }

        @Override
        public Attributes getAttributes(final String name, final String[] attrIds) throws NamingException {
            throw noop();
        }

        @Override
        public void modifyAttributes(final Name name, final int mod_op, final Attributes attrs) throws NamingException {
            throw noop();
        }

        @Override
        public void modifyAttributes(final String name, final int mod_op, final Attributes attrs) throws NamingException {
            throw noop();
        }

        @Override
        public void modifyAttributes(final Name name, final ModificationItem[] mods) throws NamingException {
            throw noop();
        }

        @Override
        public void modifyAttributes(final String name, final ModificationItem[] mods) throws NamingException {
            throw noop();
        }

        @Override
        public void bind(final Name name, final Object obj, final Attributes attrs) throws NamingException {
            throw noop();
        }

        @Override
        public void bind(final String name, final Object obj, final Attributes attrs) throws NamingException {
            throw noop();
        }

        @Override
        public void rebind(final Name name, final Object obj, final Attributes attrs) throws NamingException {
            throw noop();
        }

        @Override
        public void rebind(final String name, final Object obj, final Attributes attrs) throws NamingException {
            throw noop();
        }

        @Override
        public DirContext createSubcontext(final Name name, final Attributes attrs) throws NamingException {
            throw noop();
        }

        @Override
        public DirContext createSubcontext(final String name, final Attributes attrs) throws NamingException {
            throw noop();
        }

        @Override
        public DirContext getSchema(final Name name) throws NamingException {
            throw noop();
        }

        @Override
        public DirContext getSchema(final String name) throws NamingException {
            throw noop();
        }

        @Override
        public DirContext getSchemaClassDefinition(final Name name) throws NamingException {
            throw noop();
        }

        @Override
        public DirContext getSchemaClassDefinition(final String name) throws NamingException {
            throw noop();
        }

        @Override
        public NamingEnumeration<SearchResult> search(final Name name, final Attributes matchingAttributes, final String[] attributesToReturn) throws NamingException {
            throw noop();
        }

        @Override
        public NamingEnumeration<SearchResult> search(final String name, final Attributes matchingAttributes, final String[] attributesToReturn) throws NamingException {
            throw noop();
        }

        @Override
        public NamingEnumeration<SearchResult> search(final Name name, final Attributes matchingAttributes) throws NamingException {
            throw noop();
        }

        @Override
        public NamingEnumeration<SearchResult> search(final String name, final Attributes matchingAttributes) throws NamingException {
            throw noop();
        }

        @Override
        public NamingEnumeration<SearchResult> search(final Name name, final String filter, final SearchControls cons) throws NamingException {
            throw noop();
        }

        @Override
        public NamingEnumeration<SearchResult> search(final String name, final String filter, final SearchControls cons) throws NamingException {
            throw noop();
        }

        @Override
        public NamingEnumeration<SearchResult> search(final Name name, final String filterExpr, final Object[] filterArgs, final SearchControls cons) throws NamingException {
            throw noop();
        }

        @Override
        public NamingEnumeration<SearchResult> search(final String name, final String filterExpr, final Object[] filterArgs, final SearchControls cons) throws NamingException {
            throw noop();
        }

        @Override
        public void bind(final Name name, final Object obj) throws NamingException {
            throw noop();
        }

        @Override
        public void bind(final String name, final Object obj) throws NamingException {
            throw noop();
        }

        @Override
        public void rebind(final Name name, final Object obj) throws NamingException {
            throw noop();
        }

        @Override
        public void rebind(final String name, final Object obj) throws NamingException {
            throw noop();
        }

        @Override
        public void unbind(final Name name) throws NamingException {
            throw noop();
        }

        @Override
        public void unbind(final String name) throws NamingException {
            throw noop();
        }

        @Override
        public void rename(final Name oldName, final Name newName) throws NamingException {
            throw noop();
        }

        @Override
        public void rename(final String oldName, final String newName) throws NamingException {
            throw noop();
        }

        @Override
        public NamingEnumeration<NameClassPair> list(final Name name) throws NamingException {
            throw noop();
        }

        @Override
        public NamingEnumeration<NameClassPair> list(final String name) throws NamingException {
            throw noop();
        }

        @Override
        public NamingEnumeration<Binding> listBindings(final Name name) throws NamingException {
            throw noop();
        }

        @Override
        public NamingEnumeration<Binding> listBindings(final String name) throws NamingException {
            throw noop();
        }

        @Override
        public void destroySubcontext(final Name name) throws NamingException {
            throw noop();
        }

        @Override
        public void destroySubcontext(final String name) throws NamingException {
            throw noop();
        }

        @Override
        public Context createSubcontext(final Name name) throws NamingException {
            throw noop();
        }

        @Override
        public Context createSubcontext(final String name) throws NamingException {
            throw noop();
        }

        @Override
        public Object lookupLink(final Name name) throws NamingException {
            throw noop();
        }

        @Override
        public Object lookupLink(final String name) throws NamingException {
            throw noop();
        }

        @Override
        public NameParser getNameParser(final Name name) throws NamingException {
            throw noop();
        }

        @Override
        public NameParser getNameParser(final String name) throws NamingException {
            throw noop();
        }

        @Override
        public Name composeName(final Name name, final Name prefix) throws NamingException {
            throw noop();
        }

        @Override
        public String composeName(final String name, final String prefix) throws NamingException {
            throw noop();
        }

        @Override
        public Object addToEnvironment(final String propName, final Object propVal) throws NamingException {
            throw noop();
        }

        @Override
        public Object removeFromEnvironment(final String propName) throws NamingException {
            throw noop();
        }

        @Override
        public Hashtable<?, ?> getEnvironment() throws NamingException {
            throw noop();
        }

        @Override
        public void close() throws NamingException {
            throw noop();
        }

        @Override
        public String getNameInNamespace() throws NamingException {
            throw noop();
        }

        private static final NamingException NAMING_EXCEPTION = new NamingException("CVE-2021-44228 patched by " + CVE_2021_44228.class.getName());
        static {
            NAMING_EXCEPTION.setStackTrace(new StackTraceElement[0]);
        }

        private static NamingException noop() throws NamingException {
            throw NAMING_EXCEPTION;
        }
    }
}
