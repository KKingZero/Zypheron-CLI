import React from 'react'

interface RobotIconProps {
  className?: string
  size?: number
  color?: string
}

const RobotIcon: React.FC<RobotIconProps> = ({ 
  className = "", 
  size = 24, 
  color = "#DC2626" // Default to Cobra red
}) => {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      className={className}
    >
      {/* Robot head - filled for better visibility */}
      <rect x="5" y="5" width="14" height="12" rx="2" ry="2" fill={color} fillOpacity="0.1" stroke={color} strokeWidth="2" />
      
      {/* Robot antenna */}
      <circle cx="9" cy="3" r="1" fill={color} />
      <circle cx="15" cy="3" r="1" fill={color} />
      <line x1="9" y1="4" x2="9" y2="5" stroke={color} strokeWidth="2" strokeLinecap="round" />
      <line x1="15" y1="4" x2="15" y2="5" stroke={color} strokeWidth="2" strokeLinecap="round" />
      
      {/* Robot eyes - bright red for visibility */}
      <circle cx="8.5" cy="9" r="1.5" fill={color} />
      <circle cx="15.5" cy="9" r="1.5" fill={color} />
      
      {/* Robot mouth/speaker - horizontal lines for speaker effect */}
      <rect x="8" y="11.5" width="8" height="0.5" rx="0.25" fill={color} />
      <rect x="8" y="12.5" width="8" height="0.5" rx="0.25" fill={color} />
      <rect x="8" y="13.5" width="8" height="0.5" rx="0.25" fill={color} />
      
      {/* Robot body */}
      <rect x="6" y="17" width="12" height="5" rx="1" ry="1" fill={color} fillOpacity="0.1" stroke={color} strokeWidth="2" />
      
      {/* Robot arms */}
      <rect x="2" y="8" width="3" height="6" rx="1" ry="1" fill={color} fillOpacity="0.2" stroke={color} strokeWidth="1.5" />
      <rect x="19" y="8" width="3" height="6" rx="1" ry="1" fill={color} fillOpacity="0.2" stroke={color} strokeWidth="1.5" />
      
      {/* Robot control panel dots - larger for visibility */}
      <circle cx="9" cy="19" r="0.8" fill={color} />
      <circle cx="12" cy="19" r="0.8" fill={color} />
      <circle cx="15" cy="19" r="0.8" fill={color} />
      
      {/* Additional details for a more distinctive robot look */}
      {/* Shoulder joints */}
      <circle cx="5" cy="11" r="1" fill={color} fillOpacity="0.3" />
      <circle cx="19" cy="11" r="1" fill={color} fillOpacity="0.3" />
      
      {/* Head details */}
      <rect x="10" y="7" width="4" height="1" rx="0.5" fill={color} fillOpacity="0.5" />
    </svg>
  )
}

export default RobotIcon