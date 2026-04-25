// HatLogo.tsx — векторный логотип tidex6 (React, TypeScript)
// Brand colors: #9945FF (Solana Purple), #14F195 (Solana Green)

import React, { type SVGProps } from 'react';

export interface HatLogoProps extends Omit<SVGProps<SVGSVGElement>, 'fill'> {
  /** Размер по горизонтали в пикселях (height вычисляется по соотношению 624:374) */
  size?: number;
  /** Цвет в моно-режиме (если gradient=false) */
  color?: string;
  /** Включить brand gradient */
  gradient?: boolean;
  /** Стартовый цвет gradient (по умолчанию Solana Purple) */
  gradientFrom?: string;
  /** Конечный цвет gradient (по умолчанию Solana Green) */
  gradientTo?: string;
  /** Опциональный средний stop (например '#19B4D4' для более насыщенной середины) */
  gradientMid?: string;
  /** Угол поворота gradient: 0 = горизонталь, 45 = диагональ, 90 = вертикаль */
  angle?: number;
}

const HatLogo: React.FC<HatLogoProps> = ({
  size = 64,
  color = '#9945FF',
  gradient = false,
  gradientFrom = '#9945FF',
  gradientTo = '#14F195',
  gradientMid,
  angle = 0,
  className = '',
  ...rest
}) => {
  const gradId = React.useId();
  const fill = gradient ? `url(#${gradId})` : color;
  const transform = angle ? `rotate(${angle} 0.5 0.5)` : undefined;

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 624 374"
      width={size}
      height={(size * 374) / 624}
      className={className}
      {...rest}
    >
      {gradient && (
        <defs>
          <linearGradient
            id={gradId}
            x1="0" y1="0" x2="1" y2="0"
            gradientTransform={transform}
          >
            <stop offset="0%" stopColor={gradientFrom} />
            {gradientMid && <stop offset="50%" stopColor={gradientMid} />}
            <stop offset="100%" stopColor={gradientTo} />
          </linearGradient>
        </defs>
      )}
      <g fill={fill}>
        <path
          fillRule="evenodd"
          d="M 0 291 a 312 82 0 0 1 624 0 a 312 82 0 0 1 -624 0 Z M 38 265 a 274 59 0 0 0 548 0 a 274 59 0 0 0 -548 0 Z"
        />
        <path d="M 96 200 a 216 200 0 0 1 432 0 L 528 271 a 300 84 0 0 1 -432 0 Z" />
      </g>
    </svg>
  );
};

export default HatLogo;
