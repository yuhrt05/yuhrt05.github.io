import type { LocalImageService } from 'astro'
import sharp from 'astro/assets/services/sharp'

const customSharpService: LocalImageService = {
    ...sharp,
    transform: (inputBuffer, transformOptions, imageConfig) => {
        // Preserve original format and set quality to 95
        const options = {
            ...transformOptions,
            quality: transformOptions.quality ?? 95,
            format: transformOptions.format ?? undefined, // Keep original format (PNG)
        }

        // Call the base Sharp service with our modified options
        return sharp.transform(inputBuffer, options, imageConfig)
    },
}

export default customSharpService
