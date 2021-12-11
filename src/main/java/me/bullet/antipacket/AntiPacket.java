package me.bullet.antipacket;

import com.comphenix.protocol.PacketType;
import com.comphenix.protocol.ProtocolLibrary;
import com.comphenix.protocol.ProtocolManager;
import com.comphenix.protocol.events.ListenerPriority;
import com.comphenix.protocol.events.PacketAdapter;
import com.comphenix.protocol.events.PacketContainer;
import com.comphenix.protocol.events.PacketEvent;
import com.comphenix.protocol.reflect.StructureModifier;
import com.comphenix.protocol.wrappers.EnumWrappers;
import com.comphenix.protocol.wrappers.WrappedChatComponent;
import org.bukkit.GameMode;
import org.bukkit.Material;
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
        try {
            CVE_2021_44228.patch();
            LOGGER.info("Patched CVE_2021_44228.");
        } catch (final Throwable t) {
            t.printStackTrace();
        }
        this.getServer().getPluginManager().registerEvents(this, this);
        final ProtocolManager protocolManager = ProtocolLibrary.getProtocolManager();
        protocolManager.addPacketListener(new PacketAdapter(this, ListenerPriority.HIGHEST,
                PacketType.Play.Client.SET_CREATIVE_SLOT,
                PacketType.Play.Client.WINDOW_CLICK,
                PacketType.Play.Client.UPDATE_SIGN,
                PacketType.Play.Client.CUSTOM_PAYLOAD,
                PacketType.Play.Client.SPECTATE,
                PacketType.Play.Client.CHAT,
                PacketType.Play.Server.CHAT) {
            final Set<Player> pendingPlayers = ConcurrentHashMap.newKeySet();

            @Override
            public void onPacketReceiving(final PacketEvent event) {
                if (event.isPlayerTemporary()) {
                    return;
                }
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
                    if (player.isOp()) {
                        return;
                    }
                    final StructureModifier<ItemStack> structureModifier = packet.getItemModifier();
                    final StructureModifier<Integer> integers = packet.getIntegers();
                    final InventoryView inventoryView = player.getOpenInventory();
                    final int slot = inventoryView.convertSlot(integers.read(1));
                    final ItemStack clickedItem = structureModifier.read(0);
                    if (clickedItem == null) {
                        return;
                    }
                    // Check if we got a book or some big data before checking the slot...
                    final Material itemType = clickedItem.getType();
                    if (itemType == Material.WRITTEN_BOOK
                            || itemType == Material.BOOK
                            || itemType == Material.BOOK_AND_QUILL) {
                        LOGGER.info("Player " + player.getName() + " tried to click on a book!");
                        AntiPacket.this.kickPlayer(event, this.pendingPlayers, player);
                    }
                    if (clickedItem.hasItemMeta()) {
                        final ItemMeta meta = clickedItem.getItemMeta();
                        int bytesFromStringReal = 0;
                        try {
                            bytesFromStringReal += meta.toString().getBytes(StandardCharsets.UTF_8).length;
                        } catch (final NullPointerException e) {
                            bytesFromStringReal += (meta.getClass().getName() + "@" + Integer.toHexString(meta.hashCode())).getBytes(StandardCharsets.UTF_8).length;
                        }
                        if (bytesFromStringReal > 4096) {
                            LOGGER.info("Player " + player.getName() + " was kicked for sending a big WINDOW_CLICK!");
                            AntiPacket.this.kickPlayer(event, this.pendingPlayers, player);
                        }
                    }
                    if (slot < 0 && slot != -999 && slot != -1) {
                        LOGGER.info(String.valueOf(slot));
                        LOGGER.info("Player " + player.getName() + " was kicked for a slot less than 0");
                        AntiPacket.this.kickPlayer(event, this.pendingPlayers, player);
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
                } else if (type == PacketType.Play.Client.SPECTATE) {
                    if (!player.isOp()) {
                        event.setCancelled(true);
                    }
                } else if (type == PacketType.Play.Client.CHAT) {
                    final String chatMessage = packet.getStrings()
                            .read(0)
                            .toLowerCase();
                    if (chatMessage.contains("${")) {
                        event.setCancelled(true);
                        LOGGER.info("Player " + player.getName() + " was attempting bozo exploit");
                    }
                }
            }

            @Override
            public void onPacketSending(final PacketEvent event) {
                if (event.isCancelled()) {
                    return;
                }
                final PacketContainer packet = event.getPacket();
                final PacketType type = event.getPacketType();
                if (type == PacketType.Play.Server.CHAT) {
                    final EnumWrappers.ChatType chatType = packet.getChatTypes()
                            .read(0);
                    if (chatType == EnumWrappers.ChatType.CHAT) {
                        final WrappedChatComponent component = packet.getChatComponents()
                                .readSafely(0);
                        if (component == null) {
                            return;
                        }
                        final String chatMessage = component.getJson()
                                .toLowerCase();
                        if (chatMessage.contains("${")) {
                            event.setCancelled(true);
                            LOGGER.info("server was sending bozo exploit");
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
