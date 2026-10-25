import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.commons.ClassRemapper;
import org.objectweb.asm.commons.Remapper;

/**
 * Build-time only: moves the bundled ASM into the agent's own package and
 * rewrites every reference to it, so the agent's copy can never clash with the
 * ASM a mod loader puts on the same class path.
 *
 * <p>Usage: {@code java Relocate <staging directory> <from prefix> <to prefix>},
 * prefixes in internal form such as {@code org/objectweb/asm/}.
 */
public final class Relocate {
    private Relocate() {
    }

    public static void main(String[] arguments) throws IOException {
        Path root = Paths.get(arguments[0]);
        final String from = arguments[1];
        final String to = arguments[2];
        Remapper remapper = new Remapper() {
            @Override
            public String map(String internalName) {
                return internalName.startsWith(from)
                    ? to + internalName.substring(from.length())
                    : internalName;
            }
        };
        List<Path> classes = new ArrayList<Path>();
        try (Stream<Path> files = Files.walk(root)) {
            files.filter(path -> path.toString().endsWith(".class")).forEach(classes::add);
        }
        for (Path path : classes) {
            String name = root.relativize(path).toString().replace('\\', '/');
            if (name.endsWith("module-info.class")) {
                // A module descriptor would name the jar after ASM.
                Files.delete(path);
                continue;
            }
            ClassReader reader = new ClassReader(Files.readAllBytes(path));
            ClassWriter writer = new ClassWriter(0);
            reader.accept(new ClassRemapper(writer, remapper), 0);
            String internal = name.substring(0, name.length() - ".class".length());
            Path target = root.resolve(remapper.map(internal) + ".class");
            if (!target.equals(path)) {
                Files.delete(path);
            }
            Files.createDirectories(target.getParent());
            Files.write(target, writer.toByteArray());
        }
    }
}
