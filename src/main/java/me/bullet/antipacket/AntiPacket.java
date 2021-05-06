package me.bullet.antipacket;

import com.comphenix.protocol.PacketType;
import com.comphenix.protocol.ProtocolLibrary;
import com.comphenix.protocol.ProtocolManager;
import com.comphenix.protocol.events.ListenerPriority;
import com.comphenix.protocol.events.PacketAdapter;
import com.comphenix.protocol.events.PacketContainer;
import com.comphenix.protocol.events.PacketEvent;
import com.comphenix.protocol.reflect.StructureModifier;
import org.bukkit.GameMode;
import org.bukkit.entity.Player;
import org.bukkit.event.Listener;
import org.bukkit.inventory.InventoryView;
import org.bukkit.inventory.ItemStack;
import org.bukkit.inventory.meta.ItemMeta;
import org.bukkit.plugin.java.JavaPlugin;

import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

public class AntiPacket extends JavaPlugin implements Listener {

    private static final String KICK_MESSAGE = "\uD83D\uDC7D";

    private static final Logger LOGGER = Logger.getLogger("AntiPacket");

    @Override
    public void onEnable() {
        this.getServer().getPluginManager().registerEvents(this, this);
        final ProtocolManager protocolManager = ProtocolLibrary.getProtocolManager();
        protocolManager.addPacketListener(new PacketAdapter(this, ListenerPriority.HIGHEST,
                PacketType.Play.Client.SET_CREATIVE_SLOT,
                PacketType.Play.Client.WINDOW_CLICK,
                PacketType.Play.Client.UPDATE_SIGN,
                PacketType.Play.Client.CUSTOM_PAYLOAD) {
            final Set<Player> pendingPlayers = ConcurrentHashMap.newKeySet();

            @Override
            public void onPacketReceiving(final PacketEvent event) {
                if (event.isCancelled()) {
                    return;
                }
                final Player player = event.getPlayer();
                if (player == null) {
                    return;
                }
                final PacketType type = event.getPacketType();
                if (this.pendingPlayers.contains(player)) {
                    LOGGER.info("Player " + player.getName() + " who was pending for kick sent " + type.name());
                    event.setCancelled(true);
                    return;
                }
                if (!player.isOnline()) {
                    LOGGER.info("Player " + player.getName() + " who was offline sent " + type.name());
                    event.setCancelled(true);
                    return;
                }
                final PacketContainer packet = event.getPacket();
                if (type == PacketType.Play.Client.SET_CREATIVE_SLOT) {
                    if (player.getGameMode() != GameMode.CREATIVE) {
                        LOGGER.info("Player " + player.getName() + " was kicked for sending SET_CREATIVE_SLOT without creative!");
                        AntiPacket.this.kickPlayer(event, this.pendingPlayers, player);
                    }
                } else if (type == PacketType.Play.Client.WINDOW_CLICK) {
                    final StructureModifier<ItemStack> structureModifier = packet.getItemModifier();
                    final StructureModifier<Integer> integers = packet.getIntegers();
                    final InventoryView inventoryView = player.getOpenInventory();
                    final int slot = inventoryView.convertSlot(integers.readSafely(1));
                    if (slot < 0 && slot != -999 && slot != -1) {
                        LOGGER.info("Player " + player.getName() + " was kicked for chinese PingBypass");
                        AntiPacket.this.kickPlayer(event, this.pendingPlayers, player);
                    } else if (structureModifier.size() > 0 && slot > 0) {
                        final ItemStack clickedItem = structureModifier.readSafely(0);
                        if (clickedItem == null) {
                            return;
                        }
                        if (clickedItem.hasItemMeta()) {
                            final ItemMeta meta = clickedItem.getItemMeta();
                            int bytesFromStringReal = 0;
                            try {
                                bytesFromStringReal += meta.toString().getBytes(StandardCharsets.UTF_8).length;
                            } catch (final NullPointerException e) {
                                bytesFromStringReal += (meta.getClass().getName() + "@" + Integer.toHexString(meta.hashCode())).getBytes(StandardCharsets.UTF_8).length;
                            }
                            if (bytesFromStringReal > 512) {
                                LOGGER.info("Player " + player.getName() + " was kicked for sending a big WINDOW_CLICK!");
                                AntiPacket.this.kickPlayer(event, this.pendingPlayers, player);
                            }
                        }
                    }
                } else if (type == PacketType.Play.Client.UPDATE_SIGN) {
                    if (player.getGameMode() != GameMode.CREATIVE) {
                        LOGGER.info("Player " + player.getName() + " was kicked for sending a sign update without creative!");
                        AntiPacket.this.kickPlayer(event, this.pendingPlayers, player);
                    }
                } else if (type == PacketType.Play.Client.CUSTOM_PAYLOAD) {
                    final StructureModifier<String> strings = packet.getStrings();
                    final String channel = strings.read(0);
                    if (player.getGameMode() != GameMode.CREATIVE) {
                        if (channel.equals("MC|BEdit")
                                || channel.equals("MC|BSign")
                                || channel.equals("MC|BOpen")) {
                            LOGGER.info("Player " + player.getName() + " was kicked for sending a book payload without creative!");
                            AntiPacket.this.kickPlayer(event, this.pendingPlayers, player);
                        } else if (channel.isEmpty()) {
                            LOGGER.info("Player " + player.getName() + " was kicked for sending an invalid payload!");
                            AntiPacket.this.kickPlayer(event, this.pendingPlayers, player);
                        }
                    }
                }
            }
        });
    }

    private void kickPlayer(final PacketEvent event, final Set<Player> pendingPlayers, final Player player) {
        event.setCancelled(true);
        pendingPlayers.add(player);
        this.getServer().getScheduler().scheduleSyncDelayedTask(this, () -> {
            player.kickPlayer(KICK_MESSAGE);
            pendingPlayers.remove(player);
        });
    }
}
