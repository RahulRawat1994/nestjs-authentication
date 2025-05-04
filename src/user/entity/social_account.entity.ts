import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  ManyToOne,
  JoinColumn,
} from 'typeorm';
import { User } from './user.entity';

@Entity()
export class SocialAccount {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => User, (user) => user.socialAccounts, { onDelete: 'CASCADE' })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column()
  provider: string; // 'google', 'facebook', 'linkedin', etc.

  @Column({ unique: true })
  providerId: string; // e.g., Google ID, Facebook ID

  @Column({ nullable: true })
  avatar: string;

  @Column({ nullable: true })
  accessToken: string; // Store Google Access Token here

  @Column({ nullable: true })
  refreshToken: string; // Store Google Refresh Token here

  @Column({ type: 'timestamp', default: () => 'CURRENT_TIMESTAMP' })
  linked_at: Date;
}
