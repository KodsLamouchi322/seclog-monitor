// Déconnexion : supprime la session côté serveur puis revient à la page de connexion.
document.addEventListener("click", async (e) => {
  const link = e.target.closest("[data-logout]");
  if (!link) return;
  e.preventDefault();
  try { await fetch("/auth/logout", { method: "POST" }); } catch (err) { /* on redirige quand même */ }
  window.location.href = "/login";
});
