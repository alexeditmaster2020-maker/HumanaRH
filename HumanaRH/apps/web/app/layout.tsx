import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "HumanaRH | Gestão de Pessoas",
  description:
    "Plataforma integrada de gestão de pessoas e Departamento Pessoal.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="pt-BR">
      <body>{children}</body>
    </html>
  );
}