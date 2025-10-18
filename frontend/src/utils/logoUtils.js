/**
 * Logo Detection Utility
 * Automatically detects which logo format is available
 */

// Possible logo file formats in order of preference
const LOGO_FORMATS = ['png', 'svg', 'jpg', 'jpeg'];

// Check if a file exists by trying to load it
async function checkFileExists(url) {
  try {
    const response = await fetch(url, { method: 'HEAD' });
    return response.ok;
  } catch {
    return false;
  }
}

// Get the available logo URL for main logo
export async function getMainLogoUrl() {
  const url = `/Zypheron1.jpg`;
  if (await checkFileExists(url)) {
    return url;
  }
  // Fallback to embedded asset path
  return '/Zypheron1.jpg';
}

// Get the available logo URL for icon
export async function getIconLogoUrl() {
  const url = `/ZypheronX.jpg`;
  if (await checkFileExists(url)) {
    return url;
  }
  // Fallback to embedded asset path
  return '/ZypheronX.jpg';
}

// React hook for logo URLs
export function useLogoUrls() {
  const [mainLogo, setMainLogo] = React.useState('/Zypheron1.jpg');
  const [iconLogo, setIconLogo] = React.useState('/ZypheronX.jpg');

  React.useEffect(() => {
    getMainLogoUrl().then(setMainLogo);
    getIconLogoUrl().then(setIconLogo);
  }, []);

  return { mainLogo, iconLogo };
}

// Simple synchronous version for immediate use
export const LOGO_PATHS = {
  // Zypheron logos
  main: ['/Zypheron1.jpg'],
  icon: ['/ZypheronX.jpg']
};

export default LOGO_PATHS; 