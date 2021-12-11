package me.bullet.antipacket.util;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

public final class Reflection {
    // We can't use NativeReflectionUtil this early, but we use it to unlock the reflection filters on java 9+ so this will still work!
    public static Field stripFinal(final Field field) throws ReflectiveOperationException {
        final Field modifiersField = Field.class.getDeclaredField("modifiers");
        final boolean modifiersAccessible = modifiersField.isAccessible();
        modifiersField.setAccessible(true);
        modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
        modifiersField.setAccessible(modifiersAccessible);
        return field;
    }
}
